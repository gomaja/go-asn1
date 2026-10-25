// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s14 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s14

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	bits "math/bits"
)

func BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PC5QoSParametersExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PC5QoSParametersExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PLMNAreaBasedQMCExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PLMNAreaBasedQMCExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PSCellInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PSCellInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PagingAttemptInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PagingAttemptInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PagingEDRXInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PagingEDRXInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ProSeAuthorizedExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ProSeAuthorizedExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.RATRestrictionsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.RATRestrictionsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.RIMTransferExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.RIMTransferExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.RLFReportInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.RLFReportInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemExtIEsExtContainer is ProtocolExtensionContainer {{Bearers-SubjectToStatusTransfer-ItemExtIEs}} of TS 36.413: a list of BearersSubjectToStatusTransferItemExtIEsExtField values.
type BearersSubjectToStatusTransferItemExtIEsExtContainer []BearersSubjectToStatusTransferItemExtIEsExtField

// DAPSResponseInfoListIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{DAPSResponseInfoListIEs}} of TS 36.413: a single information element field.
type DAPSResponseInfoListIEValueProtocolIESingleContainer = DAPSResponseInfoListIEField

// BearersSubjectToStatusTransferItemExtIEsExtField is ProtocolExtensionField {{Bearers-SubjectToStatusTransfer-ItemExtIEs}} of TS 36.413: an extension field.
type BearersSubjectToStatusTransferItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue BearersSubjectToStatusTransferItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsExtField) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToStatusTransferItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToStatusTransferItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToStatusTransferItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItemExtIEsExtField{}
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
	var zero BearersSubjectToStatusTransferItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding binds COUNTValueExtended to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding struct {
	info   s00.ExtensionInfo
	codec  COUNTValueExtendedValueCodec
	inject func(COUNTValueExtended,

	) BearersSubjectToStatusTransferItemExtIEsValue

	get func(*BearersSubjectToStatusTransferItemExtIEsValue,

	) (*COUNTValueExtended,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) Codec() COUNTValueExtendedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) New(value COUNTValueExtended,

) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) Get(field *BearersSubjectToStatusTransferItemExtIEsExtField) (*COUNTValueExtended,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// COUNTValueExtendedValueCodec is the concrete ValueCodec[COUNTValueExtended].
type COUNTValueExtendedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTValueExtended,

		error)
	encode func(COUNTValueExtended,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTValueExtended, aper.DecodeState,

	) (COUNTValueExtended, aper.Snapshot,

	)
	compare func(COUNTValueExtended, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTValueExtendedValueCodec) New(value COUNTValueExtended,

) (COUNTValueExtendedAPERValue, error) {
	if c.encode == nil {
		return COUNTValueExtendedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTValueExtendedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTValueExtendedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTValueExtendedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTValueExtendedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTValueExtendedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTValueExtendedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTValueExtendedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTValueExtendedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTValueExtendedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTValueExtendedValueCodec) EncodeAPER(value COUNTValueExtendedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c COUNTValueExtendedValueCodec) encodeBudgetValue(value COUNTValueExtended,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTValueExtendedValueCodec) encodeChanged(value COUNTValueExtended,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding binds ReceiveStatusOfULPDCPSDUsExtended to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec
	inject func(s00.ReceiveStatusOfULPDCPSDUsExtended,

	) BearersSubjectToStatusTransferItemExtIEsValue

	get func(*BearersSubjectToStatusTransferItemExtIEsValue,

	) (*s00.ReceiveStatusOfULPDCPSDUsExtended,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) Codec() s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) New(value s00.ReceiveStatusOfULPDCPSDUsExtended,

) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) Get(field *BearersSubjectToStatusTransferItemExtIEsExtField) (*s00.ReceiveStatusOfULPDCPSDUsExtended,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding binds COUNTvaluePDCPSNlength18 to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding struct {
	info   s00.ExtensionInfo
	codec  COUNTvaluePDCPSNlength18ValueCodec
	inject func(COUNTvaluePDCPSNlength18,

	) BearersSubjectToStatusTransferItemExtIEsValue

	get func(*BearersSubjectToStatusTransferItemExtIEsValue,

	) (*COUNTvaluePDCPSNlength18,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) Codec() COUNTvaluePDCPSNlength18ValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) New(value COUNTvaluePDCPSNlength18,

) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) Get(field *BearersSubjectToStatusTransferItemExtIEsExtField) (*COUNTvaluePDCPSNlength18,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// COUNTvaluePDCPSNlength18ValueCodec is the concrete ValueCodec[COUNTvaluePDCPSNlength18].
type COUNTvaluePDCPSNlength18ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTvaluePDCPSNlength18,

		error)
	encode func(COUNTvaluePDCPSNlength18,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTvaluePDCPSNlength18, aper.DecodeState,

	) (COUNTvaluePDCPSNlength18, aper.Snapshot,

	)
	compare func(COUNTvaluePDCPSNlength18, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvaluePDCPSNlength18ValueCodec) New(value COUNTvaluePDCPSNlength18,

) (COUNTvaluePDCPSNlength18APERValue, error) {
	if c.encode == nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTvaluePDCPSNlength18APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvaluePDCPSNlength18ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTvaluePDCPSNlength18APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTvaluePDCPSNlength18APERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTvaluePDCPSNlength18APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTvaluePDCPSNlength18APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvaluePDCPSNlength18ValueCodec) EncodeAPER(value COUNTvaluePDCPSNlength18APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c COUNTvaluePDCPSNlength18ValueCodec) encodeBudgetValue(value COUNTvaluePDCPSNlength18,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvaluePDCPSNlength18ValueCodec) encodeChanged(value COUNTvaluePDCPSNlength18,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding binds ReceiveStatusOfULPDCPSDUsPDCPSNlength18 to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec
	inject func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

	) BearersSubjectToStatusTransferItemExtIEsValue

	get func(*BearersSubjectToStatusTransferItemExtIEsValue,

	) (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) Codec() s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) New(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) Get(field *BearersSubjectToStatusTransferItemExtIEsExtField) (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// DAPSResponseInfoListDAPSResponseInfoItemIEBinding binds DAPSResponseInfoItem to the DAPSResponseInfoListIEs object set of TS 36.413.
type DAPSResponseInfoListDAPSResponseInfoItemIEBinding struct {
	info   s00.FieldInfo
	codec  DAPSResponseInfoItemValueCodec
	inject func(DAPSResponseInfoItem,

	) DAPSResponseInfoListIEValue

	get func(*DAPSResponseInfoListIEValue,

	) (*DAPSResponseInfoItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) Codec() DAPSResponseInfoItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) New(value DAPSResponseInfoItem,

) (DAPSResponseInfoListIEField, error) {
	if b.inject == nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Value.New")
	}
	return DAPSResponseInfoListIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) Get(field *DAPSResponseInfoListIEField) (*DAPSResponseInfoItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DAPSResponseInfoItemValueCodec is the concrete ValueCodec[DAPSResponseInfoItem].
type DAPSResponseInfoItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoItem,

		error)
	encode func(DAPSResponseInfoItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoItem, aper.DecodeState,

	) (DAPSResponseInfoItem, aper.Snapshot,

	)
	compare func(DAPSResponseInfoItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoItemValueCodec) New(value DAPSResponseInfoItem,

) (DAPSResponseInfoItemAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoItemValueCodec) EncodeAPER(value DAPSResponseInfoItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoItemValueCodec) encodeBudgetValue(value DAPSResponseInfoItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoItemValueCodec) encodeChanged(value DAPSResponseInfoItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEField is ProtocolIE-Field {{DAPSResponseInfoListIEs}} of TS 36.413: an information element field.
type DAPSResponseInfoListIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         DAPSResponseInfoListIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEField) WithoutReplay() DAPSResponseInfoListIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSResponseInfoListIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSResponseInfoListIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *DAPSResponseInfoListIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoListIEField{}
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
	var zero DAPSResponseInfoListIEValue

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

// DAPSRequestInfoValueCodec is the concrete ValueCodec[DAPSRequestInfo].
type DAPSRequestInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSRequestInfo,

		error)
	encode func(DAPSRequestInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSRequestInfo, aper.DecodeState,

	) (DAPSRequestInfo, aper.Snapshot,

	)
	compare func(DAPSRequestInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSRequestInfoValueCodec) New(value DAPSRequestInfo,

) (DAPSRequestInfoAPERValue, error) {
	if c.encode == nil {
		return DAPSRequestInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSRequestInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSRequestInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSRequestInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSRequestInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSRequestInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSRequestInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSRequestInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSRequestInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSRequestInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSRequestInfoValueCodec) EncodeAPER(value DAPSRequestInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSRequestInfoValueCodec) encodeBudgetValue(value DAPSRequestInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSRequestInfoValueCodec) encodeChanged(value DAPSRequestInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CNTypeRestrictionsValueCodec is the concrete ValueCodec[CNTypeRestrictions].
type CNTypeRestrictionsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CNTypeRestrictions,

		error)
	encode func(CNTypeRestrictions,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CNTypeRestrictions, aper.DecodeState,

	) (CNTypeRestrictions, aper.Snapshot,

	)
	compare func(CNTypeRestrictions, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CNTypeRestrictionsValueCodec) New(value CNTypeRestrictions,

) (CNTypeRestrictionsAPERValue, error) {
	if c.encode == nil {
		return CNTypeRestrictionsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CNTypeRestrictionsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CNTypeRestrictionsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CNTypeRestrictionsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CNTypeRestrictionsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CNTypeRestrictionsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CNTypeRestrictionsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CNTypeRestrictionsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CNTypeRestrictionsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CNTypeRestrictionsValueCodec) EncodeAPER(value CNTypeRestrictionsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CNTypeRestrictionsValueCodec) encodeBudgetValue(value CNTypeRestrictions,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CNTypeRestrictionsValueCodec) encodeChanged(value CNTypeRestrictions,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BluetoothMeasurementConfigurationValueCodec is the concrete ValueCodec[BluetoothMeasurementConfiguration].
type BluetoothMeasurementConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BluetoothMeasurementConfiguration,

		error)
	encode func(BluetoothMeasurementConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BluetoothMeasurementConfiguration, aper.DecodeState,

	) (BluetoothMeasurementConfiguration, aper.Snapshot,

	)
	compare func(BluetoothMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BluetoothMeasurementConfigurationValueCodec) New(value BluetoothMeasurementConfiguration,

) (BluetoothMeasurementConfigurationAPERValue, error) {
	if c.encode == nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BluetoothMeasurementConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BluetoothMeasurementConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BluetoothMeasurementConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BluetoothMeasurementConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BluetoothMeasurementConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BluetoothMeasurementConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BluetoothMeasurementConfigurationValueCodec) EncodeAPER(value BluetoothMeasurementConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BluetoothMeasurementConfigurationValueCodec) encodeBudgetValue(value BluetoothMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BluetoothMeasurementConfigurationValueCodec) encodeChanged(value BluetoothMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CauseValueCodec is the concrete ValueCodec[Cause].
type CauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Cause,

		error)
	encode func(Cause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Cause, aper.DecodeState,

	) (Cause, aper.Snapshot,

	)
	compare func(Cause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CauseValueCodec) New(value Cause,

) (CauseAPERValue, error) {
	if c.encode == nil {
		return CauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CauseValueCodec) EncodeAPER(value CauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CauseValueCodec) encodeBudgetValue(value Cause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CauseValueCodec) encodeChanged(value Cause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListValueCodec is the concrete ValueCodec[DAPSResponseInfoList].
type DAPSResponseInfoListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoList,

		error)
	encode func(DAPSResponseInfoList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoList, aper.DecodeState,

	) (DAPSResponseInfoList, aper.Snapshot,

	)
	compare func(DAPSResponseInfoList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListValueCodec) New(value DAPSResponseInfoList,

) (DAPSResponseInfoListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListValueCodec) EncodeAPER(value DAPSResponseInfoListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListValueCodec) encodeBudgetValue(value DAPSResponseInfoList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListValueCodec) encodeChanged(value DAPSResponseInfoList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGMembershipInfoValueCodec is the concrete ValueCodec[CSGMembershipInfo].
type CSGMembershipInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGMembershipInfo,

		error)
	encode func(CSGMembershipInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGMembershipInfo, aper.DecodeState,

	) (CSGMembershipInfo, aper.Snapshot,

	)
	compare func(CSGMembershipInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGMembershipInfoValueCodec) New(value CSGMembershipInfo,

) (CSGMembershipInfoAPERValue, error) {
	if c.encode == nil {
		return CSGMembershipInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGMembershipInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGMembershipInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGMembershipInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGMembershipInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGMembershipInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGMembershipInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGMembershipInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGMembershipInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGMembershipInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGMembershipInfoValueCodec) EncodeAPER(value CSGMembershipInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CSGMembershipInfoValueCodec) encodeBudgetValue(value CSGMembershipInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGMembershipInfoValueCodec) encodeChanged(value CSGMembershipInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGIdListValueCodec is the concrete ValueCodec[CSGIdList].
type CSGIdListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGIdList,

		error)
	encode func(CSGIdList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGIdList, aper.DecodeState,

	) (CSGIdList, aper.Snapshot,

	)
	compare func(CSGIdList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGIdListValueCodec) New(value CSGIdList,

) (CSGIdListAPERValue, error) {
	if c.encode == nil {
		return CSGIdListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGIdListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGIdListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGIdListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGIdListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGIdListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGIdListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGIdListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGIdListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGIdListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGIdListValueCodec) EncodeAPER(value CSGIdListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CSGIdListValueCodec) encodeBudgetValue(value CSGIdList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGIdListValueCodec) encodeChanged(value CSGIdList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// Cdma2000OneXSRVCCInfoValueCodec is the concrete ValueCodec[Cdma2000OneXSRVCCInfo].
type Cdma2000OneXSRVCCInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfo,

		error)
	encode func(Cdma2000OneXSRVCCInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Cdma2000OneXSRVCCInfo, aper.DecodeState,

	) (Cdma2000OneXSRVCCInfo, aper.Snapshot,

	)
	compare func(Cdma2000OneXSRVCCInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c Cdma2000OneXSRVCCInfoValueCodec) New(value Cdma2000OneXSRVCCInfo,

) (Cdma2000OneXSRVCCInfoAPERValue, error) {
	if c.encode == nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return Cdma2000OneXSRVCCInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c Cdma2000OneXSRVCCInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (Cdma2000OneXSRVCCInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return Cdma2000OneXSRVCCInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return Cdma2000OneXSRVCCInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return Cdma2000OneXSRVCCInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c Cdma2000OneXSRVCCInfoValueCodec) EncodeAPER(value Cdma2000OneXSRVCCInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c Cdma2000OneXSRVCCInfoValueCodec) encodeBudgetValue(value Cdma2000OneXSRVCCInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c Cdma2000OneXSRVCCInfoValueCodec) encodeChanged(value Cdma2000OneXSRVCCInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ActivatedCellsListValueCodec is the concrete ValueCodec[ActivatedCellsList].
type ActivatedCellsListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ActivatedCellsList,

		error)
	encode func(ActivatedCellsList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ActivatedCellsList, aper.DecodeState,

	) (ActivatedCellsList, aper.Snapshot,

	)
	compare func(ActivatedCellsList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ActivatedCellsListValueCodec) New(value ActivatedCellsList,

) (ActivatedCellsListAPERValue, error) {
	if c.encode == nil {
		return ActivatedCellsListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ActivatedCellsListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ActivatedCellsListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ActivatedCellsListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ActivatedCellsListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ActivatedCellsListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ActivatedCellsListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ActivatedCellsListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ActivatedCellsListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ActivatedCellsListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ActivatedCellsListValueCodec) EncodeAPER(value ActivatedCellsListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ActivatedCellsListValueCodec) encodeBudgetValue(value ActivatedCellsList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ActivatedCellsListValueCodec) encodeChanged(value ActivatedCellsList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ActivatedCellsListItemValueCodec is the concrete ValueCodec[ActivatedCellsListItem].
type ActivatedCellsListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ActivatedCellsListItem,

		error)
	encode func(ActivatedCellsListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ActivatedCellsListItem, aper.DecodeState,

	) (ActivatedCellsListItem, aper.Snapshot,

	)
	compare func(ActivatedCellsListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ActivatedCellsListItemValueCodec) New(value ActivatedCellsListItem,

) (ActivatedCellsListItemAPERValue, error) {
	if c.encode == nil {
		return ActivatedCellsListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ActivatedCellsListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ActivatedCellsListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ActivatedCellsListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ActivatedCellsListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ActivatedCellsListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ActivatedCellsListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ActivatedCellsListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ActivatedCellsListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ActivatedCellsListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ActivatedCellsListItemValueCodec) EncodeAPER(value ActivatedCellsListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ActivatedCellsListItemValueCodec) encodeBudgetValue(value ActivatedCellsListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ActivatedCellsListItemValueCodec) encodeChanged(value ActivatedCellsListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AllocationAndRetentionPriorityValueCodec is the concrete ValueCodec[AllocationAndRetentionPriority].
type AllocationAndRetentionPriorityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AllocationAndRetentionPriority,

		error)
	encode func(AllocationAndRetentionPriority,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AllocationAndRetentionPriority, aper.DecodeState,

	) (AllocationAndRetentionPriority, aper.Snapshot,

	)
	compare func(AllocationAndRetentionPriority, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AllocationAndRetentionPriorityValueCodec) New(value AllocationAndRetentionPriority,

) (AllocationAndRetentionPriorityAPERValue, error) {
	if c.encode == nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AllocationAndRetentionPriorityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AllocationAndRetentionPriorityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AllocationAndRetentionPriorityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AllocationAndRetentionPriorityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AllocationAndRetentionPriorityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AllocationAndRetentionPriorityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AllocationAndRetentionPriorityValueCodec) EncodeAPER(value AllocationAndRetentionPriorityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AllocationAndRetentionPriorityValueCodec) encodeBudgetValue(value AllocationAndRetentionPriority,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AllocationAndRetentionPriorityValueCodec) encodeChanged(value AllocationAndRetentionPriority,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CGIValueCodec is the concrete ValueCodec[CGI].
type CGIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CGI,

		error)
	encode func(CGI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CGI, aper.DecodeState,

	) (CGI, aper.Snapshot,

	)
	compare func(CGI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CGIValueCodec) New(value CGI,

) (CGIAPERValue, error) {
	if c.encode == nil {
		return CGIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CGIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CGIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CGIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CGIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CGIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CGIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CGIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CGIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CGIValueCodec) EncodeAPER(value CGIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CGIValueCodec) encodeBudgetValue(value CGI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CGIValueCodec) encodeChanged(value CGI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CNTypeRestrictionsItemValueCodec is the concrete ValueCodec[CNTypeRestrictionsItem].
type CNTypeRestrictionsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CNTypeRestrictionsItem,

		error)
	encode func(CNTypeRestrictionsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CNTypeRestrictionsItem, aper.DecodeState,

	) (CNTypeRestrictionsItem, aper.Snapshot,

	)
	compare func(CNTypeRestrictionsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CNTypeRestrictionsItemValueCodec) New(value CNTypeRestrictionsItem,

) (CNTypeRestrictionsItemAPERValue, error) {
	if c.encode == nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CNTypeRestrictionsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CNTypeRestrictionsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CNTypeRestrictionsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CNTypeRestrictionsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CNTypeRestrictionsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CNTypeRestrictionsItemValueCodec) EncodeAPER(value CNTypeRestrictionsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CNTypeRestrictionsItemValueCodec) encodeBudgetValue(value CNTypeRestrictionsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CNTypeRestrictionsItemValueCodec) encodeChanged(value CNTypeRestrictionsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTvalueValueCodec is the concrete ValueCodec[COUNTvalue].
type COUNTvalueValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTvalue,

		error)
	encode func(COUNTvalue,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTvalue, aper.DecodeState,

	) (COUNTvalue, aper.Snapshot,

	)
	compare func(COUNTvalue, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvalueValueCodec) New(value COUNTvalue,

) (COUNTvalueAPERValue, error) {
	if c.encode == nil {
		return COUNTvalueAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTvalueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTvalueAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTvalueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvalueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTvalueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTvalueAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTvalueAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTvalueAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTvalueAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvalueValueCodec) EncodeAPER(value COUNTvalueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c COUNTvalueValueCodec) encodeBudgetValue(value COUNTvalue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvalueValueCodec) encodeChanged(value COUNTvalue,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGIdListItemValueCodec is the concrete ValueCodec[CSGIdListItem].
type CSGIdListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGIdListItem,

		error)
	encode func(CSGIdListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGIdListItem, aper.DecodeState,

	) (CSGIdListItem, aper.Snapshot,

	)
	compare func(CSGIdListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGIdListItemValueCodec) New(value CSGIdListItem,

) (CSGIdListItemAPERValue, error) {
	if c.encode == nil {
		return CSGIdListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGIdListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGIdListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGIdListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGIdListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGIdListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGIdListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGIdListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGIdListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGIdListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGIdListItemValueCodec) EncodeAPER(value CSGIdListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CSGIdListItemValueCodec) encodeBudgetValue(value CSGIdListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGIdListItemValueCodec) encodeChanged(value CSGIdListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CandidatePCIValueCodec is the concrete ValueCodec[CandidatePCI].
type CandidatePCIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CandidatePCI,

		error)
	encode func(CandidatePCI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CandidatePCI, aper.DecodeState,

	) (CandidatePCI, aper.Snapshot,

	)
	compare func(CandidatePCI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CandidatePCIValueCodec) New(value CandidatePCI,

) (CandidatePCIAPERValue, error) {
	if c.encode == nil {
		return CandidatePCIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CandidatePCIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CandidatePCIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CandidatePCIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CandidatePCIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CandidatePCIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CandidatePCIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CandidatePCIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CandidatePCIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CandidatePCIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CandidatePCIValueCodec) EncodeAPER(value CandidatePCIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CandidatePCIValueCodec) encodeBudgetValue(value CandidatePCI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CandidatePCIValueCodec) encodeChanged(value CandidatePCI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CandidatePCIListValueCodec is the concrete ValueCodec[CandidatePCIList].
type CandidatePCIListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CandidatePCIList,

		error)
	encode func(CandidatePCIList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CandidatePCIList, aper.DecodeState,

	) (CandidatePCIList, aper.Snapshot,

	)
	compare func(CandidatePCIList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CandidatePCIListValueCodec) New(value CandidatePCIList,

) (CandidatePCIListAPERValue, error) {
	if c.encode == nil {
		return CandidatePCIListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CandidatePCIListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CandidatePCIListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CandidatePCIListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CandidatePCIListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CandidatePCIListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CandidatePCIListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CandidatePCIListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CandidatePCIListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CandidatePCIListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CandidatePCIListValueCodec) EncodeAPER(value CandidatePCIListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CandidatePCIListValueCodec) encodeBudgetValue(value CandidatePCIList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CandidatePCIListValueCodec) encodeChanged(value CandidatePCIList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTypeValueCodec is the concrete ValueCodec[CellType].
type CellTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellType,

		error)
	encode func(CellType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellType, aper.DecodeState,

	) (CellType, aper.Snapshot,

	)
	compare func(CellType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTypeValueCodec) New(value CellType,

) (CellTypeAPERValue, error) {
	if c.encode == nil {
		return CellTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTypeValueCodec) EncodeAPER(value CellTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellTypeValueCodec) encodeBudgetValue(value CellType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTypeValueCodec) encodeChanged(value CellType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellsToActivateListValueCodec is the concrete ValueCodec[CellsToActivateList].
type CellsToActivateListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellsToActivateList,

		error)
	encode func(CellsToActivateList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellsToActivateList, aper.DecodeState,

	) (CellsToActivateList, aper.Snapshot,

	)
	compare func(CellsToActivateList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellsToActivateListValueCodec) New(value CellsToActivateList,

) (CellsToActivateListAPERValue, error) {
	if c.encode == nil {
		return CellsToActivateListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellsToActivateListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellsToActivateListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellsToActivateListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellsToActivateListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellsToActivateListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellsToActivateListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellsToActivateListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellsToActivateListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellsToActivateListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellsToActivateListValueCodec) EncodeAPER(value CellsToActivateListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellsToActivateListValueCodec) encodeBudgetValue(value CellsToActivateList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellsToActivateListValueCodec) encodeChanged(value CellsToActivateList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellsToActivateListItemValueCodec is the concrete ValueCodec[CellsToActivateListItem].
type CellsToActivateListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellsToActivateListItem,

		error)
	encode func(CellsToActivateListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellsToActivateListItem, aper.DecodeState,

	) (CellsToActivateListItem, aper.Snapshot,

	)
	compare func(CellsToActivateListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellsToActivateListItemValueCodec) New(value CellsToActivateListItem,

) (CellsToActivateListItemAPERValue, error) {
	if c.encode == nil {
		return CellsToActivateListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellsToActivateListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellsToActivateListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellsToActivateListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellsToActivateListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellsToActivateListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellsToActivateListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellsToActivateListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellsToActivateListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellsToActivateListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellsToActivateListItemValueCodec) EncodeAPER(value CellsToActivateListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellsToActivateListItemValueCodec) encodeBudgetValue(value CellsToActivateListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellsToActivateListItemValueCodec) encodeChanged(value CellsToActivateListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEItemValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEItem].
type CriticalityDiagnosticsIEItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEItem,

		error)
	encode func(CriticalityDiagnosticsIEItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsIEItem, aper.DecodeState,

	) (CriticalityDiagnosticsIEItem, aper.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsIEItemValueCodec) New(value CriticalityDiagnosticsIEItem,

) (CriticalityDiagnosticsIEItemAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsIEItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsIEItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsIEItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsIEItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsIEItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsIEItemValueCodec) EncodeAPER(value CriticalityDiagnosticsIEItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEItemValueCodec) encodeBudgetValue(value CriticalityDiagnosticsIEItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsIEItemValueCodec) encodeChanged(value CriticalityDiagnosticsIEItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEListValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEList,

		error)
	encode func(CriticalityDiagnosticsIEList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsIEList, aper.DecodeState,

	) (CriticalityDiagnosticsIEList, aper.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsIEListValueCodec) New(value CriticalityDiagnosticsIEList,

) (CriticalityDiagnosticsIEListAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsIEListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsIEListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsIEListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsIEListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsIEListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsIEListValueCodec) EncodeAPER(value CriticalityDiagnosticsIEListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEListValueCodec) encodeBudgetValue(value CriticalityDiagnosticsIEList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsIEListValueCodec) encodeChanged(value CriticalityDiagnosticsIEList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoValueCodec is the concrete ValueCodec[DAPSResponseInfo].
type DAPSResponseInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfo,

		error)
	encode func(DAPSResponseInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfo, aper.DecodeState,

	) (DAPSResponseInfo, aper.Snapshot,

	)
	compare func(DAPSResponseInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoValueCodec) New(value DAPSResponseInfo,

) (DAPSResponseInfoAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoValueCodec) EncodeAPER(value DAPSResponseInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoValueCodec) encodeBudgetValue(value DAPSResponseInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoValueCodec) encodeChanged(value DAPSResponseInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEContainer is ProtocolIE-Container {{DAPSResponseInfoListIEs}} of TS 36.413: a list of DAPSResponseInfoListIEField values.
type DAPSResponseInfoListIEContainer []DAPSResponseInfoListIEField

// PC5QoSParametersExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PC5QoSParameters-ExtIEs}} codec of TS 36.413.
func PC5QoSParametersExtIEsValueExtensionFieldTableCodec(table s00.PC5QoSParametersExtIEsValueExtensionTable) s10.PC5QoSParametersExtIEsExtFieldValueCodec {
	if !*s00.BridgePC5QoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5QoSParametersExtIEsExtFieldValueCodec{}
	}
	return func() s10.PC5QoSParametersExtIEsExtFieldValueCodec {
		sealed := s10.PC5QoSParametersExtIEsExtFieldValueCodec{}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtField, error) {
			var field s10.PC5QoSParametersExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PC5QoSParametersExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PC5QoSParametersExtIEsExtField, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PC5QoSParametersExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PLMNAreaBasedQMCExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PLMNAreaBasedQMC-ExtIEs}} codec of TS 36.413.
func PLMNAreaBasedQMCExtIEsValueExtensionFieldTableCodec(table s00.PLMNAreaBasedQMCExtIEsValueExtensionTable) s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec {
	if !*s00.BridgePLMNAreaBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec{}
	}
	return func() s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec {
		sealed := s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec{}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtField, error) {
			var field s10.PLMNAreaBasedQMCExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PLMNAreaBasedQMCExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtField, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PSCellInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PSCellInformation-ExtIEs}} codec of TS 36.413.
func PSCellInformationExtIEsValueExtensionFieldTableCodec(table s00.PSCellInformationExtIEsValueExtensionTable) s10.PSCellInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PSCellInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.PSCellInformationExtIEsExtFieldValueCodec {
		sealed := s10.PSCellInformationExtIEsExtFieldValueCodec{}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PSCellInformationExtIEsExtField, error) {
			var field s10.PSCellInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PSCellInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PSCellInformationExtIEsExtField, options aper.DecodeState) (s10.PSCellInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PSCellInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingAttemptInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PagingAttemptInformation-ExtIEs}} codec of TS 36.413.
func PagingAttemptInformationExtIEsValueExtensionFieldTableCodec(table s00.PagingAttemptInformationExtIEsValueExtensionTable) s10.PagingAttemptInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePagingAttemptInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PagingAttemptInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.PagingAttemptInformationExtIEsExtFieldValueCodec {
		sealed := s10.PagingAttemptInformationExtIEsExtFieldValueCodec{}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtField, error) {
			var field s10.PagingAttemptInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PagingAttemptInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtField, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingEDRXInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Paging-eDRXInformation-ExtIEs}} codec of TS 36.413.
func PagingEDRXInformationExtIEsValueExtensionFieldTableCodec(table s00.PagingEDRXInformationExtIEsValueExtensionTable) s10.PagingEDRXInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PagingEDRXInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.PagingEDRXInformationExtIEsExtFieldValueCodec {
		sealed := s10.PagingEDRXInformationExtIEsExtFieldValueCodec{}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PagingEDRXInformationExtIEsExtField, error) {
			var field s10.PagingEDRXInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PagingEDRXInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PagingEDRXInformationExtIEsExtField, options aper.DecodeState) (s10.PagingEDRXInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PagingEDRXInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ProSeAuthorizedExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ProSeAuthorized-ExtIEs}} codec of TS 36.413.
func ProSeAuthorizedExtIEsValueExtensionFieldTableCodec(table s00.ProSeAuthorizedExtIEsValueExtensionTable) s10.ProSeAuthorizedExtIEsExtFieldValueCodec {
	if !*s00.BridgeProSeAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ProSeAuthorizedExtIEsExtFieldValueCodec{}
	}
	return func() s10.ProSeAuthorizedExtIEsExtFieldValueCodec {
		sealed := s10.ProSeAuthorizedExtIEsExtFieldValueCodec{}
		*s10.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ProSeAuthorizedExtIEsExtField, error) {
			var field s10.ProSeAuthorizedExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeProSeAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ProSeAuthorizedExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeProSeAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ProSeAuthorizedExtIEsExtField, options aper.DecodeState) (s10.ProSeAuthorizedExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ProSeAuthorizedExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RATRestrictionsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RAT-RestrictionsItem-ExtIEs}} codec of TS 36.413.
func RATRestrictionsItemExtIEsValueExtensionFieldTableCodec(table s00.RATRestrictionsItemExtIEsValueExtensionTable) s10.RATRestrictionsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeRATRestrictionsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.RATRestrictionsItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.RATRestrictionsItemExtIEsExtFieldValueCodec {
		sealed := s10.RATRestrictionsItemExtIEsExtFieldValueCodec{}
		*s10.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.RATRestrictionsItemExtIEsExtField, error) {
			var field s10.RATRestrictionsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeRATRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.RATRestrictionsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeRATRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.RATRestrictionsItemExtIEsExtField, options aper.DecodeState) (s10.RATRestrictionsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.RATRestrictionsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RIMTransferExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RIMTransfer-ExtIEs}} codec of TS 36.413.
func RIMTransferExtIEsValueExtensionFieldTableCodec(table s00.RIMTransferExtIEsValueExtensionTable) s10.RIMTransferExtIEsExtFieldValueCodec {
	if !*s00.BridgeRIMTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s10.RIMTransferExtIEsExtFieldValueCodec{}
	}
	return func() s10.RIMTransferExtIEsExtFieldValueCodec {
		sealed := s10.RIMTransferExtIEsExtFieldValueCodec{}
		*s10.BridgeRIMTransferExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.RIMTransferExtIEsExtField, error) {
			var field s10.RIMTransferExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeRIMTransferExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.RIMTransferExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeRIMTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeRIMTransferExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.RIMTransferExtIEsExtField, options aper.DecodeState) (s10.RIMTransferExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeRIMTransferExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.RIMTransferExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeRIMTransferExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RLFReportInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RLFReportInformation-ExtIEs}} codec of TS 36.413.
func RLFReportInformationExtIEsValueExtensionFieldTableCodec(table s00.RLFReportInformationExtIEsValueExtensionTable) s10.RLFReportInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeRLFReportInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.RLFReportInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.RLFReportInformationExtIEsExtFieldValueCodec {
		sealed := s10.RLFReportInformationExtIEsExtFieldValueCodec{}
		*s10.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.RLFReportInformationExtIEsExtField, error) {
			var field s10.RLFReportInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeRLFReportInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.RLFReportInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeRLFReportInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.RLFReportInformationExtIEsExtField, options aper.DecodeState) (s10.RLFReportInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.RLFReportInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PC5QoSFlowItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PC5QoSFlowItem-ExtIEs}} codec of TS 36.413.
func PC5QoSFlowItemExtIEsValueExtensionTableCodec(table s00.PC5QoSFlowItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PC5QoSFlowItemExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5QoSFlowItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5QoSFlowItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PC5QoSFlowItemExtIEsExtContainerValueCodec {
		sealed := s10.PC5QoSFlowItemExtIEsExtContainerValueCodec{}
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5QoSFlowItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PC5QoSFlowItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PC5QoSFlowItemExtIEsExtField
					if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PC5QoSFlowItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PC5QoSFlowItemExtIEsExtContainer, options aper.DecodeState) (s10.PC5QoSFlowItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s13.BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PC5QoSFlowItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s13.BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PC5QoSParametersExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PC5QoSParameters-ExtIEs}} codec of TS 36.413.
func PC5QoSParametersExtIEsValueExtensionTableCodec(table s00.PC5QoSParametersExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PC5QoSParametersExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5QoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5QoSParametersExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PC5QoSParametersExtIEsExtContainerValueCodec {
		sealed := s10.PC5QoSParametersExtIEsExtContainerValueCodec{}
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PC5QoSParametersExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PC5QoSParametersExtIEsExtField
					if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PC5QoSParametersExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PC5QoSParametersExtIEsExtContainer, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PC5QoSParametersExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PLMNAreaBasedQMCExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PLMNAreaBasedQMC-ExtIEs}} codec of TS 36.413.
func PLMNAreaBasedQMCExtIEsValueExtensionTableCodec(table s00.PLMNAreaBasedQMCExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec {
	if !*s00.BridgePLMNAreaBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec {
		sealed := s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec{}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PLMNAreaBasedQMCExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PLMNAreaBasedQMCExtIEsExtField
					if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PLMNAreaBasedQMCExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtContainer, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PSCellInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PSCellInformation-ExtIEs}} codec of TS 36.413.
func PSCellInformationExtIEsValueExtensionTableCodec(table s00.PSCellInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PSCellInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PSCellInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PSCellInformationExtIEsExtContainerValueCodec {
		sealed := s10.PSCellInformationExtIEsExtContainerValueCodec{}
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PSCellInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PSCellInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PSCellInformationExtIEsExtField
					if err := s10.BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PSCellInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PSCellInformationExtIEsExtContainer, options aper.DecodeState) (s10.PSCellInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PSCellInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PagingAttemptInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PagingAttemptInformation-ExtIEs}} codec of TS 36.413.
func PagingAttemptInformationExtIEsValueExtensionTableCodec(table s00.PagingAttemptInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PagingAttemptInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePagingAttemptInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PagingAttemptInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PagingAttemptInformationExtIEsExtContainerValueCodec {
		sealed := s10.PagingAttemptInformationExtIEsExtContainerValueCodec{}
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PagingAttemptInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PagingAttemptInformationExtIEsExtField
					if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PagingAttemptInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtContainer, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PagingEDRXInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Paging-eDRXInformation-ExtIEs}} codec of TS 36.413.
func PagingEDRXInformationExtIEsValueExtensionTableCodec(table s00.PagingEDRXInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PagingEDRXInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PagingEDRXInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PagingEDRXInformationExtIEsExtContainerValueCodec {
		sealed := s10.PagingEDRXInformationExtIEsExtContainerValueCodec{}
		*s10.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PagingEDRXInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PagingEDRXInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PagingEDRXInformationExtIEsExtField
					if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PagingEDRXInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PagingEDRXInformationExtIEsExtContainer, options aper.DecodeState) (s10.PagingEDRXInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PagingEDRXInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ProSeAuthorizedExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ProSeAuthorized-ExtIEs}} codec of TS 36.413.
func ProSeAuthorizedExtIEsValueExtensionTableCodec(table s00.ProSeAuthorizedExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ProSeAuthorizedExtIEsExtContainerValueCodec {
	if !*s00.BridgeProSeAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ProSeAuthorizedExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ProSeAuthorizedExtIEsExtContainerValueCodec {
		sealed := s10.ProSeAuthorizedExtIEsExtContainerValueCodec{}
		*s10.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ProSeAuthorizedExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ProSeAuthorizedExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ProSeAuthorizedExtIEsExtField
					if err := s10.BridgeProSeAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ProSeAuthorizedExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeProSeAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ProSeAuthorizedExtIEsExtContainer, options aper.DecodeState) (s10.ProSeAuthorizedExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ProSeAuthorizedExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RATRestrictionsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RAT-RestrictionsItem-ExtIEs}} codec of TS 36.413.
func RATRestrictionsItemExtIEsValueExtensionTableCodec(table s00.RATRestrictionsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.RATRestrictionsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeRATRestrictionsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.RATRestrictionsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.RATRestrictionsItemExtIEsExtContainerValueCodec {
		sealed := s10.RATRestrictionsItemExtIEsExtContainerValueCodec{}
		*s10.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.RATRestrictionsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.RATRestrictionsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.RATRestrictionsItemExtIEsExtField
					if err := s10.BridgeRATRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.RATRestrictionsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeRATRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.RATRestrictionsItemExtIEsExtContainer, options aper.DecodeState) (s10.RATRestrictionsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.RATRestrictionsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RIMTransferExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RIMTransfer-ExtIEs}} codec of TS 36.413.
func RIMTransferExtIEsValueExtensionTableCodec(table s00.RIMTransferExtIEsValueExtensionTable, bounds aper.ListBounds) s10.RIMTransferExtIEsExtContainerValueCodec {
	if !*s00.BridgeRIMTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s10.RIMTransferExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.RIMTransferExtIEsExtContainerValueCodec {
		sealed := s10.RIMTransferExtIEsExtContainerValueCodec{}
		*s10.BridgeRIMTransferExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.RIMTransferExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.RIMTransferExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.RIMTransferExtIEsExtField
					if err := s10.BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgeRIMTransferExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.RIMTransferExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeRIMTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeRIMTransferExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.RIMTransferExtIEsExtContainer, options aper.DecodeState) (s10.RIMTransferExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeRIMTransferExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.RIMTransferExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeRIMTransferExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RLFReportInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RLFReportInformation-ExtIEs}} codec of TS 36.413.
func RLFReportInformationExtIEsValueExtensionTableCodec(table s00.RLFReportInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.RLFReportInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeRLFReportInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.RLFReportInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.RLFReportInformationExtIEsExtContainerValueCodec {
		sealed := s10.RLFReportInformationExtIEsExtContainerValueCodec{}
		*s10.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.RLFReportInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.RLFReportInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.RLFReportInformationExtIEsExtField
					if err := s10.BridgeRLFReportInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s10.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.RLFReportInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeRLFReportInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.RLFReportInformationExtIEsExtContainer, options aper.DecodeState) (s10.RLFReportInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.RLFReportInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// pC5QoSFlowItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5QoSFlowItemExtIEsValue].
type PC5QoSFlowItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PC5QoSFlowItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PC5QoSFlowItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// pC5QoSParametersExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5QoSParametersExtIEsValue].
type PC5QoSParametersExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PC5QoSParametersExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PC5QoSParametersExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PC5QoSParametersExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePC5QoSParametersExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePC5QoSParametersExtIEsExtFieldFieldReplay(v), *s10.BridgePC5QoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(v *s10.PC5QoSParametersExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePC5QoSParametersExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePC5QoSParametersExtIEsExtFieldFieldReplay(v), *s10.BridgePC5QoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}

// pLMNAreaBasedQMCExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PLMNAreaBasedQMCExtIEsValue].
type PLMNAreaBasedQMCExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PLMNAreaBasedQMCExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PLMNAreaBasedQMCExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PLMNAreaBasedQMCExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePLMNAreaBasedQMCExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldReplay(v), *s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(v *s10.PLMNAreaBasedQMCExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePLMNAreaBasedQMCExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldReplay(v), *s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}

// pSCellInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PSCellInformationExtIEsValue].
type PSCellInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PSCellInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PSCellInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PSCellInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePSCellInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePSCellInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.PSCellInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePSCellInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePSCellInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// pagingAttemptInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PagingAttemptInformationExtIEsValue].
type PagingAttemptInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PagingAttemptInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PagingAttemptInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PagingAttemptInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePagingAttemptInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePagingAttemptInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingAttemptInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.PagingAttemptInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePagingAttemptInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePagingAttemptInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingAttemptInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// pagingEDRXInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PagingEDRXInformationExtIEsValue].
type PagingEDRXInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PagingEDRXInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PagingEDRXInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PagingEDRXInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePagingEDRXInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.PagingEDRXInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePagingEDRXInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// proSeAuthorizedExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ProSeAuthorizedExtIEsValue].
type ProSeAuthorizedExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.ProSeAuthorizedExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.ProSeAuthorizedExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ProSeAuthorizedExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeProSeAuthorizedExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeProSeAuthorizedExtIEsExtFieldFieldReplay(v), *s10.BridgeProSeAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionField(v *s10.ProSeAuthorizedExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeProSeAuthorizedExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeProSeAuthorizedExtIEsExtFieldFieldReplay(v), *s10.BridgeProSeAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}

// rATRestrictionsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RATRestrictionsItemExtIEsValue].
type RATRestrictionsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RATRestrictionsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RATRestrictionsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.RATRestrictionsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRATRestrictionsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeRATRestrictionsItemExtIEsExtFieldFieldReplay(v), *s10.BridgeRATRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.RATRestrictionsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRATRestrictionsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeRATRestrictionsItemExtIEsExtFieldFieldReplay(v), *s10.BridgeRATRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// rIMTransferExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RIMTransferExtIEsValue].
type RIMTransferExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RIMTransferExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RIMTransferExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionField(v *s10.RIMTransferExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRIMTransferExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeRIMTransferExtIEsExtFieldFieldReplay(v), *s10.BridgeRIMTransferExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionField(v *s10.RIMTransferExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRIMTransferExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeRIMTransferExtIEsExtFieldFieldReplay(v), *s10.BridgeRIMTransferExtIEsExtFieldFieldWithoutReplay(v))
}

// rLFReportInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RLFReportInformationExtIEsValue].
type RLFReportInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.RLFReportInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.RLFReportInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.RLFReportInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeRLFReportInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeRLFReportInformationExtIEsExtFieldFieldReplay(v), *s10.BridgeRLFReportInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.RLFReportInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeRLFReportInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeRLFReportInformationExtIEsExtFieldFieldReplay(v), *s10.BridgeRLFReportInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// COUNTValueExtendedAPERValue is the concrete APERValue[COUNTValueExtended].
type COUNTValueExtendedAPERValue struct {
	context s00.BridgeCodecContext
	Value   COUNTValueExtended

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTValueExtendedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTValueExtendedAPERValue) WithoutReplay() COUNTValueExtendedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvaluePDCPSNlength18APERValue is the concrete APERValue[COUNTvaluePDCPSNlength18].
type COUNTvaluePDCPSNlength18APERValue struct {
	context s00.BridgeCodecContext
	Value   COUNTvaluePDCPSNlength18

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvaluePDCPSNlength18APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvaluePDCPSNlength18APERValue) WithoutReplay() COUNTvaluePDCPSNlength18APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoItemAPERValue is the concrete APERValue[DAPSResponseInfoItem].
type DAPSResponseInfoItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSResponseInfoItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoItemAPERValue) WithoutReplay() DAPSResponseInfoItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSRequestInfoAPERValue is the concrete APERValue[DAPSRequestInfo].
type DAPSRequestInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSRequestInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSRequestInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSRequestInfoAPERValue) WithoutReplay() DAPSRequestInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CNTypeRestrictionsAPERValue is the concrete APERValue[CNTypeRestrictions].
type CNTypeRestrictionsAPERValue struct {
	context s00.BridgeCodecContext
	Value   CNTypeRestrictions

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CNTypeRestrictionsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsAPERValue) WithoutReplay() CNTypeRestrictionsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BluetoothMeasurementConfigurationAPERValue is the concrete APERValue[BluetoothMeasurementConfiguration].
type BluetoothMeasurementConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   BluetoothMeasurementConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BluetoothMeasurementConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BluetoothMeasurementConfigurationAPERValue) WithoutReplay() BluetoothMeasurementConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CauseAPERValue is the concrete APERValue[Cause].
type CauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   Cause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CauseAPERValue) WithoutReplay() CauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListAPERValue is the concrete APERValue[DAPSResponseInfoList].
type DAPSResponseInfoListAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSResponseInfoList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListAPERValue) WithoutReplay() DAPSResponseInfoListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGMembershipInfoAPERValue is the concrete APERValue[CSGMembershipInfo].
type CSGMembershipInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   CSGMembershipInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGMembershipInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGMembershipInfoAPERValue) WithoutReplay() CSGMembershipInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGIdListAPERValue is the concrete APERValue[CSGIdList].
type CSGIdListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CSGIdList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGIdListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListAPERValue) WithoutReplay() CSGIdListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// Cdma2000OneXSRVCCInfoAPERValue is the concrete APERValue[Cdma2000OneXSRVCCInfo].
type Cdma2000OneXSRVCCInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   Cdma2000OneXSRVCCInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v Cdma2000OneXSRVCCInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v Cdma2000OneXSRVCCInfoAPERValue) WithoutReplay() Cdma2000OneXSRVCCInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ActivatedCellsListAPERValue is the concrete APERValue[ActivatedCellsList].
type ActivatedCellsListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ActivatedCellsList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ActivatedCellsListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ActivatedCellsListAPERValue) WithoutReplay() ActivatedCellsListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ActivatedCellsListItemAPERValue is the concrete APERValue[ActivatedCellsListItem].
type ActivatedCellsListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ActivatedCellsListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ActivatedCellsListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ActivatedCellsListItemAPERValue) WithoutReplay() ActivatedCellsListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AllocationAndRetentionPriorityAPERValue is the concrete APERValue[AllocationAndRetentionPriority].
type AllocationAndRetentionPriorityAPERValue struct {
	context s00.BridgeCodecContext
	Value   AllocationAndRetentionPriority

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AllocationAndRetentionPriorityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AllocationAndRetentionPriorityAPERValue) WithoutReplay() AllocationAndRetentionPriorityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CGIAPERValue is the concrete APERValue[CGI].
type CGIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CGI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CGIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CGIAPERValue) WithoutReplay() CGIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CNTypeRestrictionsItemAPERValue is the concrete APERValue[CNTypeRestrictionsItem].
type CNTypeRestrictionsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CNTypeRestrictionsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CNTypeRestrictionsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsItemAPERValue) WithoutReplay() CNTypeRestrictionsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvalueAPERValue is the concrete APERValue[COUNTvalue].
type COUNTvalueAPERValue struct {
	context s00.BridgeCodecContext
	Value   COUNTvalue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvalueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvalueAPERValue) WithoutReplay() COUNTvalueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGIdListItemAPERValue is the concrete APERValue[CSGIdListItem].
type CSGIdListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CSGIdListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGIdListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListItemAPERValue) WithoutReplay() CSGIdListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CandidatePCIAPERValue is the concrete APERValue[CandidatePCI].
type CandidatePCIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CandidatePCI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CandidatePCIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CandidatePCIAPERValue) WithoutReplay() CandidatePCIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CandidatePCIListAPERValue is the concrete APERValue[CandidatePCIList].
type CandidatePCIListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CandidatePCIList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CandidatePCIListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CandidatePCIListAPERValue) WithoutReplay() CandidatePCIListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTypeAPERValue is the concrete APERValue[CellType].
type CellTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTypeAPERValue) WithoutReplay() CellTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellsToActivateListAPERValue is the concrete APERValue[CellsToActivateList].
type CellsToActivateListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellsToActivateList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellsToActivateListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellsToActivateListAPERValue) WithoutReplay() CellsToActivateListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellsToActivateListItemAPERValue is the concrete APERValue[CellsToActivateListItem].
type CellsToActivateListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellsToActivateListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellsToActivateListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellsToActivateListItemAPERValue) WithoutReplay() CellsToActivateListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEItemAPERValue is the concrete APERValue[CriticalityDiagnosticsIEItem].
type CriticalityDiagnosticsIEItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnosticsIEItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsIEItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEItemAPERValue) WithoutReplay() CriticalityDiagnosticsIEItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEListAPERValue is the concrete APERValue[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnosticsIEList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsIEListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEListAPERValue) WithoutReplay() CriticalityDiagnosticsIEListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoAPERValue is the concrete APERValue[DAPSResponseInfo].
type DAPSResponseInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSResponseInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoAPERValue) WithoutReplay() DAPSResponseInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemExtIEsIEField uses the ProtocolIE-Field shape for object set Bearers-SubjectToStatusTransfer-ItemExtIEs of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         BearersSubjectToStatusTransferItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsIEField) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToStatusTransferItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToStatusTransferItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToStatusTransferItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItemExtIEsIEField{}
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
	var zero BearersSubjectToStatusTransferItemExtIEsValue

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

// BearersSubjectToStatusTransferItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set Bearers-SubjectToStatusTransfer-ItemExtIEs of TS 36.413: a list of BearersSubjectToStatusTransferItemExtIEsIEField values.
type BearersSubjectToStatusTransferItemExtIEsIEContainer []BearersSubjectToStatusTransferItemExtIEsIEField

// DAPSResponseInfoListIEValueERABIEContainerListValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEValueERABIEContainerList].
type DAPSResponseInfoListIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, error)
	encode  func(DAPSResponseInfoListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEValueERABIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot)
	compare func(DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) New(value DAPSResponseInfoListIEValueERABIEContainerList) (DAPSResponseInfoListIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) EncodeAPER(value DAPSResponseInfoListIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) encodeChanged(value DAPSResponseInfoListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueERABIEContainerList is E-RAB-IE-ContainerList {{DAPSResponseInfoListIEs}} of TS 36.413: a list of information element fields.
type DAPSResponseInfoListIEValueERABIEContainerList []DAPSResponseInfoListIEValueProtocolIESingleContainer

// BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemExtIEsExtField].
type BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, error)
	encode  func(BearersSubjectToStatusTransferItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) New(value BearersSubjectToStatusTransferItemExtIEsExtField) (BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemExtIEsExtContainer].
type BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, error)
	encode  func(BearersSubjectToStatusTransferItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) New(value BearersSubjectToStatusTransferItemExtIEsExtContainer) (BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEFieldValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEField].
type DAPSResponseInfoListIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEField, error)
	encode  func(DAPSResponseInfoListIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEField, aper.DecodeState) (DAPSResponseInfoListIEField, aper.Snapshot)
	compare func(DAPSResponseInfoListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEFieldValueCodec) New(value DAPSResponseInfoListIEField) (DAPSResponseInfoListIEFieldAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEFieldValueCodec) EncodeAPER(value DAPSResponseInfoListIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEFieldValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEFieldValueCodec) encodeChanged(value DAPSResponseInfoListIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEContainerValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEContainer].
type DAPSResponseInfoListIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEContainer, error)
	encode  func(DAPSResponseInfoListIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEContainer, aper.DecodeState) (DAPSResponseInfoListIEContainer, aper.Snapshot)
	compare func(DAPSResponseInfoListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEContainerValueCodec) New(value DAPSResponseInfoListIEContainer) (DAPSResponseInfoListIEContainerAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEContainerValueCodec) EncodeAPER(value DAPSResponseInfoListIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEContainerValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEContainerValueCodec) encodeChanged(value DAPSResponseInfoListIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEValueProtocolErrorIEContainerList].
type DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, error)
	encode  func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) New(value DAPSResponseInfoListIEValueProtocolErrorIEContainerList) (DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value DAPSResponseInfoListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{DAPSResponseInfoListIEs}} of TS 36.413: a list of information element fields.
type DAPSResponseInfoListIEValueProtocolErrorIEContainerList []DAPSResponseInfoListIEValueProtocolIESingleContainer

// DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEValueProtocolIEContainerList].
type DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, error)
	encode  func(DAPSResponseInfoListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) New(value DAPSResponseInfoListIEValueProtocolIEContainerList) (DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) EncodeAPER(value DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) encodeChanged(value DAPSResponseInfoListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {DAPSResponseInfoListIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type DAPSResponseInfoListIEValueProtocolIEContainerList []DAPSResponseInfoListIEValueProtocolIESingleContainer

// DAPSResponseInfoListIEValueERABIEContainerListAPERValue is the concrete APERValue[DAPSResponseInfoListIEValueERABIEContainerList].
type DAPSResponseInfoListIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEValueERABIEContainerListAPERValue) WithoutReplay() DAPSResponseInfoListIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemExtIEsExtField].
type BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemExtIEsExtContainer].
type BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEFieldAPERValue is the concrete APERValue[DAPSResponseInfoListIEField].
type DAPSResponseInfoListIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEFieldAPERValue) WithoutReplay() DAPSResponseInfoListIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEContainerAPERValue is the concrete APERValue[DAPSResponseInfoListIEContainer].
type DAPSResponseInfoListIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEContainerAPERValue) WithoutReplay() DAPSResponseInfoListIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[DAPSResponseInfoListIEValueProtocolErrorIEContainerList].
type DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue is the concrete APERValue[DAPSResponseInfoListIEValueProtocolIEContainerList].
type DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) WithoutReplay() DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APActivatedCellsListItem(v *ActivatedCellsListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APActivatedCellsListItem(v *ActivatedCellsListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APAllocationAndRetentionPriority(v *AllocationAndRetentionPriority, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPriorityLevel(&v.PriorityLevel, s)
	s00.BridgeCaptureS1APPreEmptionCapability(&v.PreEmptionCapability, s)
	s00.BridgeCaptureS1APPreEmptionVulnerability(&v.PreEmptionVulnerability, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAllocationAndRetentionPriorityExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAllocationAndRetentionPriority(v *AllocationAndRetentionPriority, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPriorityLevel(&v.PriorityLevel, s)
	s02.BridgeCompareS1APPreEmptionCapability(&v.PreEmptionCapability, s)
	s02.BridgeCompareS1APPreEmptionVulnerability(&v.PreEmptionVulnerability, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAllocationAndRetentionPriorityExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(v *BearersSubjectToEarlyStatusTransferItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	BridgeCaptureS1APDLCOUNTPDCPSNlength(&v.DLCOUNTPDCPSNlength, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v *BearersSubjectToEarlyStatusTransferItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	BridgeCompareS1APDLCOUNTPDCPSNlength(&v.DLCOUNTPDCPSNlength, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferItemExtIEsValue(v *BearersSubjectToStatusTransferItemExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(179):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValueExtended == nil)
				if v.rowULCOUNTValueExtended != nil {
					BridgeCaptureS1APCOUNTValueExtended(v.rowULCOUNTValueExtended, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(180):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValueExtended == nil)
				if v.rowDLCOUNTValueExtended != nil {
					BridgeCaptureS1APCOUNTValueExtended(v.rowDLCOUNTValueExtended, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(181):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsExtended == nil)
				if v.rowReceiveStatusOfULPDCPSDUsExtended != nil {
					s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsExtended(v.rowReceiveStatusOfULPDCPSDUsExtended, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(217):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValuePDCPSNlength18 == nil)
				if v.rowULCOUNTValuePDCPSNlength18 != nil {
					BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.rowULCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(218):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValuePDCPSNlength18 == nil)
				if v.rowDLCOUNTValuePDCPSNlength18 != nil {
					BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.rowDLCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(219):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil)
				if v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 != nil {
					s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToStatusTransferItemExtIEsValue {
	BridgeCaptureS1APBearersSubjectToStatusTransferItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToStatusTransferItemExtIEsValue(v *BearersSubjectToStatusTransferItemExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(179):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValueExtended == nil)
				if v.rowULCOUNTValueExtended != nil {
					BridgeCompareS1APCOUNTValueExtended(v.rowULCOUNTValueExtended, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(180):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValueExtended == nil)
				if v.rowDLCOUNTValueExtended != nil {
					BridgeCompareS1APCOUNTValueExtended(v.rowDLCOUNTValueExtended, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(181):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsExtended == nil)
				if v.rowReceiveStatusOfULPDCPSDUsExtended != nil {
					s06.BridgeCompareS1APReceiveStatusOfULPDCPSDUsExtended(v.rowReceiveStatusOfULPDCPSDUsExtended, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(217):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValuePDCPSNlength18 == nil)
				if v.rowULCOUNTValuePDCPSNlength18 != nil {
					BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.rowULCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(218):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValuePDCPSNlength18 == nil)
				if v.rowDLCOUNTValuePDCPSNlength18 != nil {
					BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.rowDLCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(219):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil)
				if v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 != nil {
					s06.BridgeCompareS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToStatusTransferItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APBluetoothMeasurementConfiguration(v *BluetoothMeasurementConfiguration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBluetoothMeasConfig(&v.BluetoothMeasConfig, s)
	s.Bool(v.BluetoothMeasConfigNameList == nil)
	s00.BridgeCaptureS1APBluetoothMeasConfigNameList(&v.BluetoothMeasConfigNameList, s)
	{
		f := s.Begin()
		s.Bool(v.BtRssi == nil)
		if v.BtRssi != nil {
			s.Int(int64((*v.BtRssi)))
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeBluetoothMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBluetoothMeasurementConfiguration(v *BluetoothMeasurementConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBluetoothMeasConfig(&v.BluetoothMeasConfig, s)
	s.Bool(v.BluetoothMeasConfigNameList == nil)
	s02.BridgeCompareS1APBluetoothMeasConfigNameList(&v.BluetoothMeasConfigNameList, s)
	{
		f := s.Begin()
		s.Bool(v.BtRssi == nil)
		if v.BtRssi != nil {
			s.Int(int64((*v.BtRssi)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeBluetoothMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCGI(v *CGI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s00.BridgeCaptureS1APLAC(&v.LAC, s)
	s00.BridgeCaptureS1APCI(&v.CI, s)
	{
		f := s.Begin()
		s.Bool(v.RAC == nil)
		if v.RAC != nil {
			s00.BridgeCaptureS1APRAC(v.RAC, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCGI(v *CGI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s02.BridgeCompareS1APLAC(&v.LAC, s)
	s02.BridgeCompareS1APCI(&v.CI, s)
	{
		f := s.Begin()
		s.Bool(v.RAC == nil)
		if v.RAC != nil {
			s06.BridgeCompareS1APRAC(v.RAC, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCNTypeRestrictionsItem(v *CNTypeRestrictionsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureS1APCNType(&v.CNType, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCNTypeRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCNTypeRestrictionsItem(v *CNTypeRestrictionsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNIdentity, s)
	s02.BridgeCompareS1APCNType(&v.CNType, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCNTypeRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCOUNTValueExtended(v *COUNTValueExtended, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPDCPSNExtended(&v.PDCPSNExtended, s)
	s00.BridgeCaptureS1APHFNModified(&v.HFNModified, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCOUNTValueExtendedExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCOUNTValueExtended(v *COUNTValueExtended, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPDCPSNExtended(&v.PDCPSNExtended, s)
	s02.BridgeCompareS1APHFNModified(&v.HFNModified, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCOUNTValueExtendedExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCOUNTvalue(v *COUNTvalue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPDCPSN(&v.PDCPSN, s)
	s00.BridgeCaptureS1APHFN(&v.HFN, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCOUNTvalueExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCOUNTvalue(v *COUNTvalue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPDCPSN(&v.PDCPSN, s)
	s02.BridgeCompareS1APHFN(&v.HFN, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCOUNTvalueExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v *COUNTvaluePDCPSNlength18, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPDCPSNlength18(&v.PDCPSNlength18, s)
	s00.BridgeCaptureS1APHFNforPDCPSNlength18(&v.HFNforPDCPSNlength18, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCOUNTvaluePDCPSNlength18(v *COUNTvaluePDCPSNlength18, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPDCPSNlength18(&v.PDCPSNlength18, s)
	s02.BridgeCompareS1APHFNforPDCPSNlength18(&v.HFNforPDCPSNlength18, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCSGIdListItem(v *CSGIdListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCSGId(&v.CSGId, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCSGIdListItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCSGIdListItem(v *CSGIdListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCSGId(&v.CSGId, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCSGIdListItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCSGMembershipInfo(v *CSGMembershipInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCSGMembershipStatus(&v.CSGMembershipStatus, s)
	s00.BridgeCaptureS1APCSGId(&v.CSGId, s)
	{
		f := s.Begin()
		s.Bool(v.CellAccessMode == nil)
		if v.CellAccessMode != nil {
			s00.BridgeCaptureS1APCellAccessMode(v.CellAccessMode, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PLMNidentity == nil)
		if v.PLMNidentity != nil {
			s00.BridgeCaptureS1APPLMNidentity(v.PLMNidentity, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCSGMembershipInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCSGMembershipInfo(v *CSGMembershipInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCSGMembershipStatus(&v.CSGMembershipStatus, s)
	s02.BridgeCompareS1APCSGId(&v.CSGId, s)
	{
		f := s.Begin()
		s.Bool(v.CellAccessMode == nil)
		if v.CellAccessMode != nil {
			s02.BridgeCompareS1APCellAccessMode(v.CellAccessMode, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PLMNidentity == nil)
		if v.PLMNidentity != nil {
			s07.BridgeCompareS1APPLMNidentity(v.PLMNidentity, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCSGMembershipInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCandidatePCI(v *CandidatePCI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.PCI))
	s.Bytes(v.EARFCN)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCandidatePCI(v *CandidatePCI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.PCI))
	s.Bytes(v.EARFCN)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCause(v *Cause, s *aper.SemanticCapture) {
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
	case s00.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				s00.BridgeCaptureS1APCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceTransport:
		{
			f := s.Begin()
			s.Bool(v.Transport == nil)
			if v.Transport != nil {
				s00.BridgeCaptureS1APCauseTransport(v.Transport, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceNas:
		{
			f := s.Begin()
			s.Bool(v.Nas == nil)
			if v.Nas != nil {
				s00.BridgeCaptureS1APCauseNas(v.Nas, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				s00.BridgeCaptureS1APCauseProtocol(v.Protocol, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				s00.BridgeCaptureS1APCauseMisc(v.Misc, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCause(v *Cause, s *aper.SemanticComparison) {
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
	case s00.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				s02.BridgeCompareS1APCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceTransport:
		{
			f := s.Begin()
			s.Bool(v.Transport == nil)
			if v.Transport != nil {
				s02.BridgeCompareS1APCauseTransport(v.Transport, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceNas:
		{
			f := s.Begin()
			s.Bool(v.Nas == nil)
			if v.Nas != nil {
				s02.BridgeCompareS1APCauseNas(v.Nas, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				s02.BridgeCompareS1APCauseProtocol(v.Protocol, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				s02.BridgeCompareS1APCauseMisc(v.Misc, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCdma2000OneXSRVCCInfo(v *Cdma2000OneXSRVCCInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCdma2000OneXMEID(&v.Cdma2000OneXMEID, s)
	s00.BridgeCaptureS1APCdma2000OneXMSI(&v.Cdma2000OneXMSI, s)
	s00.BridgeCaptureS1APCdma2000OneXPilot(&v.Cdma2000OneXPilot, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCdma2000OneXSRVCCInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCdma2000OneXSRVCCInfo(v *Cdma2000OneXSRVCCInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCdma2000OneXMEID(&v.Cdma2000OneXMEID, s)
	s02.BridgeCompareS1APCdma2000OneXMSI(&v.Cdma2000OneXMSI, s)
	s02.BridgeCompareS1APCdma2000OneXPilot(&v.Cdma2000OneXPilot, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCdma2000OneXSRVCCInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellType(v *CellType, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCellSize(&v.CellSize, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellType(v *CellType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCellSize(&v.CellSize, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellsToActivateListItem(v *CellsToActivateListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellsToActivateListItem(v *CellsToActivateListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCriticalityDiagnosticsIEItem(v *CriticalityDiagnosticsIEItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCriticality(&v.IECriticality, s)
	s00.BridgeCaptureS1APProtocolIEID(&v.IEID, s)
	s00.BridgeCaptureS1APTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCriticalityDiagnosticsIEItem(v *CriticalityDiagnosticsIEItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCriticality(&v.IECriticality, s)
	s02.BridgeCompareS1APProtocolIEID(&v.IEID, s)
	s07.BridgeCompareS1APTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSRequestInfo(v *DAPSRequestInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.DAPSIndicator))
	s.Bool(v.IEExtensions == nil)
	s13.BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDAPSRequestInfo(v *DAPSRequestInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.DAPSIndicator))
	s.Bool(v.IEExtensions == nil)
	s13.BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfo(v *DAPSResponseInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Dapsresponseindicator))
	s.Bool(v.IEExtensions == nil)
	s13.BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDAPSResponseInfo(v *DAPSResponseInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Dapsresponseindicator))
	s.Bool(v.IEExtensions == nil)
	s13.BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfoItem(v *DAPSResponseInfoItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	BridgeCaptureS1APDAPSResponseInfo(&v.DAPSResponseInfo, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDAPSResponseInfoItem(v *DAPSResponseInfoItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	BridgeCompareS1APDAPSResponseInfo(&v.DAPSResponseInfo, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfoListIEValue(v *DAPSResponseInfoListIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(319):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSResponseInfoItem == nil)
				if v.rowDAPSResponseInfoItem != nil {
					BridgeCaptureS1APDAPSResponseInfoItem(v.rowDAPSResponseInfoItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DAPSResponseInfoListIEValue) captureSemantics(s aper.SemanticCapture) DAPSResponseInfoListIEValue {
	BridgeCaptureS1APDAPSResponseInfoListIEValue(&v, &s)
	return v
}
func BridgeCompareS1APDAPSResponseInfoListIEValue(v *DAPSResponseInfoListIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(319):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSResponseInfoItem == nil)
				if v.rowDAPSResponseInfoItem != nil {
					BridgeCompareS1APDAPSResponseInfoItem(v.rowDAPSResponseInfoItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DAPSResponseInfoListIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APDAPSResponseInfoListIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APDLCOUNTPDCPSNlength(v *DLCOUNTPDCPSNlength, s *aper.SemanticCapture) {
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
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength12 == nil)
			if v.DLCOUNTValuePDCPSNlength12 != nil {
				BridgeCaptureS1APCOUNTvalue(v.DLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength15 == nil)
			if v.DLCOUNTValuePDCPSNlength15 != nil {
				BridgeCaptureS1APCOUNTValueExtended(v.DLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength18 == nil)
			if v.DLCOUNTValuePDCPSNlength18 != nil {
				BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.DLCOUNTValuePDCPSNlength18, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDLCOUNTPDCPSNlength(v *DLCOUNTPDCPSNlength, s *aper.SemanticComparison) {
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
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength12 == nil)
			if v.DLCOUNTValuePDCPSNlength12 != nil {
				BridgeCompareS1APCOUNTvalue(v.DLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength15 == nil)
			if v.DLCOUNTValuePDCPSNlength15 != nil {
				BridgeCompareS1APCOUNTValueExtended(v.DLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength18 == nil)
			if v.DLCOUNTValuePDCPSNlength18 != nil {
				BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.DLCOUNTValuePDCPSNlength18, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}

// AllocationAndRetentionPriority represents the ASN.1 type AllocationAndRetentionPriority (SEQUENCE).
type AllocationAndRetentionPriority struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	PriorityLevel           s00.PriorityLevel                                    `asn1:"tag:0,context,implicit"`
	PreEmptionCapability    s00.PreEmptionCapability                             `asn1:"tag:1,context,implicit"`
	PreEmptionVulnerability s00.PreEmptionVulnerability                          `asn1:"tag:2,context,implicit"`
	IEExtensions            s07.AllocationAndRetentionPriorityExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                                 `asn1:"-" json:"-"`
	extCount                int64                                                `asn1:"-" json:"-"`
	extPresent              []bool                                               `asn1:"-" json:"-"`
	extData                 [][]byte                                             `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// BearersSubjectToEarlyStatusTransferItem represents the ASN.1 type Bearers-SubjectToEarlyStatusTransfer-Item (SEQUENCE).
type BearersSubjectToEarlyStatusTransferItem struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	ERABID              s00.ERABID                                                    `asn1:"tag:0,context,implicit"`
	DLCOUNTPDCPSNlength DLCOUNTPDCPSNlength                                           `asn1:"tag:1,context,explicit"`
	IEExtensions        s07.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                                          `asn1:"-" json:"-"`
	extCount            int64                                                         `asn1:"-" json:"-"`
	extPresent          []bool                                                        `asn1:"-" json:"-"`
	extData             [][]byte                                                      `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                                             `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                                        `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// BluetoothMeasurementConfiguration represents the ASN.1 type BluetoothMeasurementConfiguration (SEQUENCE).
type BluetoothMeasurementConfiguration struct {
	replay                           aper.Snapshot
	stream                           aper.WireSpan
	received                         bool
	withoutReplay                    bool
	receivedAbsolute                 bool
	receivedBytes                    aper.WireSpan
	receivedLocation                 aper.Location
	BluetoothMeasConfig              s00.BluetoothMeasConfig                                 `asn1:"tag:0,context,implicit"`
	BluetoothMeasConfigNameList      s00.BluetoothMeasConfigNameList                         `asn1:"tag:1,context,implicit,optional" json:"BluetoothMeasConfigNameList,omitzero"`
	bluetoothMeasConfigNameListIndef bool                                                    `asn1:"-" json:"-"`
	BtRssi                           *int64                                                  `asn1:"tag:2,context,implicit,optional" json:"BtRssi,omitempty"`
	IEExtensions                     s07.BluetoothMeasurementConfigurationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                bool                                                    `asn1:"-" json:"-"`
	extCount                         int64                                                   `asn1:"-" json:"-"`
	extPresent                       []bool                                                  `asn1:"-" json:"-"`
	extData                          [][]byte                                                `asn1:"-" json:"-"`
	perPadding                       aper.FinalPadding                                       `asn1:"-" json:"-"`
	perExtPadding                    []aper.CompletePadding                                  `asn1:"-" json:"-"`
	extOrigin                        []aper.OpaqueOrigin
	extWire                          []aper.WireSpan
}

// Cause represents the ASN.1 CHOICE type Cause.
type Cause struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding   `json:"-"`
	perOpenTypePadding aper.CompletePadding   `json:"-"`
	UnknownExtension   *aper.ChoiceExtension  `json:"UnknownExtension,omitempty"`
	RadioNetwork       *s00.CauseRadioNetwork `json:"RadioNetwork,omitempty"`
	Transport          *s00.CauseTransport    `json:"Transport,omitempty"`
	Nas                *s00.CauseNas          `json:"Nas,omitempty"`
	Protocol           *s00.CauseProtocol     `json:"Protocol,omitempty"`
	Misc               *s00.CauseMisc         `json:"Misc,omitempty"`
}

// Cdma2000OneXSRVCCInfo represents the ASN.1 type Cdma2000OneXSRVCCInfo (SEQUENCE).
type Cdma2000OneXSRVCCInfo struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	Cdma2000OneXMEID  s00.Cdma2000OneXMEID                        `asn1:"tag:0,context,implicit"`
	Cdma2000OneXMSI   s00.Cdma2000OneXMSI                         `asn1:"tag:1,context,implicit"`
	Cdma2000OneXPilot s00.Cdma2000OneXPilot                       `asn1:"tag:2,context,implicit"`
	IEExtensions      s07.Cdma2000OneXSRVCCInfoExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                        `asn1:"-" json:"-"`
	extCount          int64                                       `asn1:"-" json:"-"`
	extPresent        []bool                                      `asn1:"-" json:"-"`
	extData           [][]byte                                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// CellType represents the ASN.1 type CellType (SEQUENCE).
type CellType struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	CellSize          s00.CellSize                   `asn1:"tag:0,context,implicit"`
	IEExtensions      s07.CellTypeExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                           `asn1:"-" json:"-"`
	extCount          int64                          `asn1:"-" json:"-"`
	extPresent        []bool                         `asn1:"-" json:"-"`
	extData           [][]byte                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// CGI represents the ASN.1 type CGI (SEQUENCE).
type CGI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity          `asn1:"tag:0,context,implicit"`
	LAC               s00.LAC                   `asn1:"tag:1,context,implicit"`
	CI                s00.CI                    `asn1:"tag:2,context,implicit"`
	RAC               *s00.RAC                  `asn1:"tag:3,context,implicit,optional" json:"RAC,omitempty"`
	IEExtensions      s07.CGIExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                      `asn1:"-" json:"-"`
	extCount          int64                     `asn1:"-" json:"-"`
	extPresent        []bool                    `asn1:"-" json:"-"`
	extData           [][]byte                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type CNTypeRestrictions = []CNTypeRestrictionsItem

// CNTypeRestrictionsItem represents the ASN.1 type CNTypeRestrictions-Item (SEQUENCE).
type CNTypeRestrictionsItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNIdentity      s00.PLMNidentity                             `asn1:"tag:0,context,implicit"`
	CNType            s00.CNType                                   `asn1:"tag:1,context,implicit"`
	IEExtensions      s07.CNTypeRestrictionsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                         `asn1:"-" json:"-"`
	extCount          int64                                        `asn1:"-" json:"-"`
	extPresent        []bool                                       `asn1:"-" json:"-"`
	extData           [][]byte                                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type CSGIdList = []CSGIdListItem

// CSGIdListItem represents the ASN.1 type CSG-IdList-Item (SEQUENCE).
type CSGIdListItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	CSGId             s00.CSGId                           `asn1:"tag:0,context,implicit"`
	IEExtensions      s07.CSGIdListItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                `asn1:"-" json:"-"`
	extCount          int64                               `asn1:"-" json:"-"`
	extPresent        []bool                              `asn1:"-" json:"-"`
	extData           [][]byte                            `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                   `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding              `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// COUNTvalue represents the ASN.1 type COUNTvalue (SEQUENCE).
type COUNTvalue struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PDCPSN            s00.PDCPSN                       `asn1:"tag:0,context,implicit"`
	HFN               s00.HFN                          `asn1:"tag:1,context,implicit"`
	IEExtensions      s07.COUNTvalueExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                             `asn1:"-" json:"-"`
	extCount          int64                            `asn1:"-" json:"-"`
	extPresent        []bool                           `asn1:"-" json:"-"`
	extData           [][]byte                         `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// COUNTValueExtended represents the ASN.1 type COUNTValueExtended (SEQUENCE).
type COUNTValueExtended struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PDCPSNExtended    s00.PDCPSNExtended                       `asn1:"tag:0,context,implicit"`
	HFNModified       s00.HFNModified                          `asn1:"tag:1,context,implicit"`
	IEExtensions      s07.COUNTValueExtendedExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                     `asn1:"-" json:"-"`
	extCount          int64                                    `asn1:"-" json:"-"`
	extPresent        []bool                                   `asn1:"-" json:"-"`
	extData           [][]byte                                 `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// COUNTvaluePDCPSNlength18 represents the ASN.1 type COUNTvaluePDCP-SNlength18 (SEQUENCE).
type COUNTvaluePDCPSNlength18 struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	PDCPSNlength18       s00.PDCPSNlength18                             `asn1:"tag:0,context,implicit"`
	HFNforPDCPSNlength18 s00.HFNforPDCPSNlength18                       `asn1:"tag:1,context,implicit"`
	IEExtensions         s07.COUNTvaluePDCPSNlength18ExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                           `asn1:"-" json:"-"`
	extCount             int64                                          `asn1:"-" json:"-"`
	extPresent           []bool                                         `asn1:"-" json:"-"`
	extData              [][]byte                                       `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}
type CriticalityDiagnosticsIEList = []CriticalityDiagnosticsIEItem

// CriticalityDiagnosticsIEItem represents the ASN.1 type CriticalityDiagnostics-IE-Item (SEQUENCE).
type CriticalityDiagnosticsIEItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	IECriticality     s00.Criticality                                    `asn1:"tag:0,context,implicit"`
	IEID              s00.ProtocolIEID                                   `asn1:"tag:1,context,implicit"`
	TypeOfError       s00.TypeOfError                                    `asn1:"tag:2,context,implicit"`
	IEExtensions      s07.CriticalityDiagnosticsIEItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// DAPSRequestInfo represents the ASN.1 type DAPSRequestInfo (SEQUENCE).
type DAPSRequestInfo struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	DAPSIndicator     int64                                 `asn1:"tag:0,context,implicit"`
	IEExtensions      s07.DAPSRequestInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type DAPSResponseInfoList = []DAPSResponseInfoListIEValueProtocolIESingleContainer

// DAPSResponseInfoItem represents the ASN.1 type DAPSResponseInfoItem (SEQUENCE).
type DAPSResponseInfoItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                 `asn1:"tag:0,context,implicit"`
	DAPSResponseInfo  DAPSResponseInfo                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.DAPSResponseInfoItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                       `asn1:"-" json:"-"`
	extCount          int64                                      `asn1:"-" json:"-"`
	extPresent        []bool                                     `asn1:"-" json:"-"`
	extData           [][]byte                                   `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// DAPSResponseInfo represents the ASN.1 type DAPSResponseInfo (SEQUENCE).
type DAPSResponseInfo struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	Dapsresponseindicator int64                                  `asn1:"tag:0,context,implicit"`
	IEExtensions          s08.DAPSResponseInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                   `asn1:"-" json:"-"`
	extCount              int64                                  `asn1:"-" json:"-"`
	extPresent            []bool                                 `asn1:"-" json:"-"`
	extData               [][]byte                               `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// DLCOUNTPDCPSNlength represents the ASN.1 CHOICE type DLCOUNT-PDCP-SNlength.
type DLCOUNTPDCPSNlength struct {
	replay                     aper.Snapshot
	stream                     aper.WireSpan
	received                   bool
	withoutReplay              bool
	receivedAbsolute           bool
	receivedBytes              aper.WireSpan
	receivedLocation           aper.Location
	Choice                     int
	perPadding                 aper.CompletePadding      `json:"-"`
	perOpenTypePadding         aper.CompletePadding      `json:"-"`
	UnknownExtension           *aper.ChoiceExtension     `json:"UnknownExtension,omitempty"`
	DLCOUNTValuePDCPSNlength12 *COUNTvalue               `json:"DLCOUNTValuePDCPSNlength12,omitempty"`
	DLCOUNTValuePDCPSNlength15 *COUNTValueExtended       `json:"DLCOUNTValuePDCPSNlength15,omitempty"`
	DLCOUNTValuePDCPSNlength18 *COUNTvaluePDCPSNlength18 `json:"DLCOUNTValuePDCPSNlength18,omitempty"`
}

// MarshalAPER encodes AllocationAndRetentionPriority to APER format.
func (v *AllocationAndRetentionPriority) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AllocationAndRetentionPriority) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.PriorityLevel), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(15), false); err != nil {
		return fmt.Errorf("encoding priorityLevel: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PreEmptionCapability), 2, false); err != nil {
		return fmt.Errorf("encoding pre-emptionCapability: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PreEmptionVulnerability), 2, false); err != nil {
		return fmt.Errorf("encoding pre-emptionVulnerability: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AllocationAndRetentionPriority from APER format.
func (v *AllocationAndRetentionPriority) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AllocationAndRetentionPriority with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AllocationAndRetentionPriority) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AllocationAndRetentionPriority")
	}
	bb.EnterComponent("AllocationAndRetentionPriority")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AllocationAndRetentionPriority")
	}
	padding, err := aper.CaptureFinalBits(bb, "AllocationAndRetentionPriority")
	if err != nil {
		return runtime.WrapDecodePath(err, "AllocationAndRetentionPriority")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AllocationAndRetentionPriority) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AllocationAndRetentionPriority{}
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
	val_prioritylevel, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(15), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PriorityLevel")
	}
	v.PriorityLevel = s00.PriorityLevel(val_prioritylevel)
	val_preemptioncapability, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "PreEmptionCapability"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PreEmptionCapability")
	}
	v.PreEmptionCapability = s00.PreEmptionCapability(val_preemptioncapability)
	val_preemptionvulnerability, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "PreEmptionVulnerability"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PreEmptionVulnerability")
	}
	v.PreEmptionVulnerability = s00.PreEmptionVulnerability(val_preemptionvulnerability)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.AllocationAndRetentionPriorityExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.AllocationAndRetentionPriorityExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes BearersSubjectToEarlyStatusTransferItem to APER format.
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := v.DLCOUNTPDCPSNlength.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dLCOUNT-PDCP-SNlength: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes BearersSubjectToEarlyStatusTransferItem from APER format.
func (v *BearersSubjectToEarlyStatusTransferItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BearersSubjectToEarlyStatusTransferItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BearersSubjectToEarlyStatusTransferItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	bb.EnterComponent("BearersSubjectToEarlyStatusTransferItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *BearersSubjectToEarlyStatusTransferItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToEarlyStatusTransferItem{}
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
	toleranceMark_dlcountpdcpsnlength := bb.EnterComponent("DLCOUNTPDCPSNlength")
	if err := v.DLCOUNTPDCPSNlength.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	bb.LeaveComponent(toleranceMark_dlcountpdcpsnlength)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.BearersSubjectToEarlyStatusTransferItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes BluetoothMeasurementConfiguration to APER format.
func (v *BluetoothMeasurementConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *BluetoothMeasurementConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, v.BluetoothMeasConfigNameList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.BtRssi != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.BluetoothMeasConfig), 1, true); err != nil {
		return fmt.Errorf("encoding bluetoothMeasConfig: %w", err)
	}
	if v.BluetoothMeasConfigNameList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.BluetoothMeasConfigNameList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_bluetoothmeasconfignamelist, fragmentLength_bluetoothmeasconfignamelist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_bluetoothmeasconfignamelist < 0 || fragmentOffset_bluetoothmeasconfignamelist > int64(len(v.BluetoothMeasConfigNameList)) || fragmentLength_bluetoothmeasconfignamelist < 0 || fragmentLength_bluetoothmeasconfignamelist > int64(len(v.BluetoothMeasConfigNameList[fragmentOffset_bluetoothmeasconfignamelist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.BluetoothMeasConfigNameList[fragmentOffset_bluetoothmeasconfignamelist : fragmentOffset_bluetoothmeasconfignamelist+fragmentLength_bluetoothmeasconfignamelist] {
				if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 248, true); err != nil {
					return fmt.Errorf("encoding bluetoothMeasConfigNameList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding bluetoothMeasConfigNameList: %w", err)
		}
	}
	if v.BtRssi != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.BtRssi), 1, true); err != nil {
			return fmt.Errorf("encoding bt-rssi: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes BluetoothMeasurementConfiguration from APER format.
func (v *BluetoothMeasurementConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BluetoothMeasurementConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BluetoothMeasurementConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
	}
	bb.EnterComponent("BluetoothMeasurementConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "BluetoothMeasurementConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *BluetoothMeasurementConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BluetoothMeasurementConfiguration{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_bluetoothmeasconfignamelist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_btrssi, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_bluetoothmeasconfig, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BluetoothMeasConfig"})
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfig")
	}
	v.BluetoothMeasConfig = s00.BluetoothMeasConfig(val_bluetoothmeasconfig)
	if opt_bluetoothmeasconfignamelist {
		toleranceMark_bluetoothmeasconfignamelist := bb.EnterComponent("BluetoothMeasConfigNameList")
		tmp_bluetoothmeasconfignamelist := make(s00.BluetoothMeasConfigNameList, 0)
		_, errCollection_bluetoothmeasconfignamelist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_bluetoothmeasconfignamelist, fragmentLength_bluetoothmeasconfignamelist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
			if fragmentOffset_bluetoothmeasconfignamelist < 0 || fragmentLength_bluetoothmeasconfignamelist < 0 || fragmentLength_bluetoothmeasconfignamelist > int64(^uint(0)>>1) || fragmentOffset_bluetoothmeasconfignamelist > int64(^uint(0)>>1)-fragmentLength_bluetoothmeasconfignamelist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_bluetoothmeasconfignamelist; i++ {
				val, err := aper.DecodeOctetStringAligned(bb, 1, 248, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("BluetoothMeasConfigNameList[%d]", fragmentOffset_bluetoothmeasconfignamelist+i))
				}
				if next, err := aper.AppendValues(bb, tmp_bluetoothmeasconfignamelist, val); err != nil {
					return err
				} else {
					tmp_bluetoothmeasconfignamelist = next
				}
			}
			return nil
		})
		if errCollection_bluetoothmeasconfignamelist != nil {
			return runtime.WrapDecodePath(errCollection_bluetoothmeasconfignamelist, "BluetoothMeasConfigNameList")
		}
		v.BluetoothMeasConfigNameList = tmp_bluetoothmeasconfignamelist
		bb.LeaveComponent(toleranceMark_bluetoothmeasconfignamelist)
	}
	if opt_btrssi {
		val_btrssi, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BtRssi"})
		if err != nil {
			return runtime.WrapDecodePath(err, "BtRssi")
		}
		if err := aper.ChargeValue(bb, val_btrssi); err != nil {
			return err
		}
		v.BtRssi = (*int64)(bb.OwnInt64(int64(val_btrssi)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.BluetoothMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.BluetoothMeasurementConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes Cause to APER format.
func (v *Cause) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *Cause) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "Cause:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "Cause:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "Cause:", v.Choice)
	}
	isExtension := v.Choice > 5
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "Cause:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 4); err != nil {
		return err
	}
	switch v.Choice {
	case s00.CauseChoiceRadioNetwork:
		if v.RadioNetwork == nil {
			return fmt.Errorf("choice alternative radioNetwork is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.RadioNetwork), 36, true); err != nil {
			return fmt.Errorf("encoding radioNetwork: %w", err)
		}
	case s00.CauseChoiceTransport:
		if v.Transport == nil {
			return fmt.Errorf("choice alternative transport is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Transport), 2, true); err != nil {
			return fmt.Errorf("encoding transport: %w", err)
		}
	case s00.CauseChoiceNas:
		if v.Nas == nil {
			return fmt.Errorf("choice alternative nas is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Nas), 4, true); err != nil {
			return fmt.Errorf("encoding nas: %w", err)
		}
	case s00.CauseChoiceProtocol:
		if v.Protocol == nil {
			return fmt.Errorf("choice alternative protocol is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Protocol), 7, true); err != nil {
			return fmt.Errorf("encoding protocol: %w", err)
		}
	case s00.CauseChoiceMisc:
		if v.Misc == nil {
			return fmt.Errorf("choice alternative misc is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Misc), 6, true); err != nil {
			return fmt.Errorf("encoding misc: %w", err)
		}
	default:
		return fmt.Errorf("unknown Cause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Cause from APER format.
func (v *Cause) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Cause with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Cause) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	bb.EnterComponent("Cause")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	padding, err := aper.CaptureFinalBits(bb, "Cause")
	if err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *Cause) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cause{}
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
		if err := openExtension.ObserveUnknown(bb); err != nil {
			return err
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 4)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.CauseChoiceRadioNetwork:
		val_radionetwork, err := aper.DecodeEnumeratedAligned(bb, 36, true, aper.EnumerationSource{KnownExtensions: 9, Path: "RadioNetwork"})
		if err != nil {
			return runtime.WrapDecodePath(err, "RadioNetwork")
		}
		tmp_radionetwork := s00.CauseRadioNetwork(val_radionetwork)
		if err := aper.ChargeValue(bb, tmp_radionetwork); err != nil {
			return err
		}
		v.RadioNetwork = (*s00.CauseRadioNetwork)(bb.OwnInt64(int64(tmp_radionetwork)))

	case s00.CauseChoiceTransport:
		val_transport, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Transport"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Transport")
		}
		tmp_transport := s00.CauseTransport(val_transport)
		if err := aper.ChargeValue(bb, tmp_transport); err != nil {
			return err
		}
		v.Transport = (*s00.CauseTransport)(bb.OwnInt64(int64(tmp_transport)))

	case s00.CauseChoiceNas:
		val_nas, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 3, Path: "Nas"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Nas")
		}
		tmp_nas := s00.CauseNas(val_nas)
		if err := aper.ChargeValue(bb, tmp_nas); err != nil {
			return err
		}
		v.Nas = (*s00.CauseNas)(bb.OwnInt64(int64(tmp_nas)))

	case s00.CauseChoiceProtocol:
		val_protocol, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Protocol"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Protocol")
		}
		tmp_protocol := s00.CauseProtocol(val_protocol)
		if err := aper.ChargeValue(bb, tmp_protocol); err != nil {
			return err
		}
		v.Protocol = (*s00.CauseProtocol)(bb.OwnInt64(int64(tmp_protocol)))

	case s00.CauseChoiceMisc:
		val_misc, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Misc"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Misc")
		}
		tmp_misc := s00.CauseMisc(val_misc)
		if err := aper.ChargeValue(bb, tmp_misc); err != nil {
			return err
		}
		v.Misc = (*s00.CauseMisc)(bb.OwnInt64(int64(tmp_misc)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes Cdma2000OneXSRVCCInfo to APER format.
func (v *Cdma2000OneXSRVCCInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.Cdma2000OneXMEID), 0, 0, false); err != nil {
		return fmt.Errorf("encoding cdma2000OneXMEID: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.Cdma2000OneXMSI), 0, 0, false); err != nil {
		return fmt.Errorf("encoding cdma2000OneXMSI: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.Cdma2000OneXPilot), 0, 0, false); err != nil {
		return fmt.Errorf("encoding cdma2000OneXPilot: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes Cdma2000OneXSRVCCInfo from APER format.
func (v *Cdma2000OneXSRVCCInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Cdma2000OneXSRVCCInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Cdma2000OneXSRVCCInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfo")
	}
	bb.EnterComponent("Cdma2000OneXSRVCCInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "Cdma2000OneXSRVCCInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *Cdma2000OneXSRVCCInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cdma2000OneXSRVCCInfo{}
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
	val_cdma2000onexmeid, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXMEID")
	}
	v.Cdma2000OneXMEID = s00.Cdma2000OneXMEID(val_cdma2000onexmeid)
	val_cdma2000onexmsi, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXMSI")
	}
	v.Cdma2000OneXMSI = s00.Cdma2000OneXMSI(val_cdma2000onexmsi)
	val_cdma2000onexpilot, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXPilot")
	}
	v.Cdma2000OneXPilot = s00.Cdma2000OneXPilot(val_cdma2000onexpilot)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.Cdma2000OneXSRVCCInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.Cdma2000OneXSRVCCInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CellType to APER format.
func (v *CellType) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellType) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.CellSize), 4, true); err != nil {
		return fmt.Errorf("encoding cell-Size: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCellTypeExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellType from APER format.
func (v *CellType) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellType with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellType) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellType")
	}
	bb.EnterComponent("CellType")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellType")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellType")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellType")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellType) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellType{}
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
	val_cellsize, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellSize"})
	if err != nil {
		return runtime.WrapDecodePath(err, "CellSize")
	}
	v.CellSize = s00.CellSize(val_cellsize)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.CellTypeExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CellTypeExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCellTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CGI to APER format.
func (v *CGI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CGI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, v.RAC != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.LAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding lAC: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.CI), 2, 2, true); err != nil {
		return fmt.Errorf("encoding cI: %w", err)
	}
	if v.RAC != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.RAC), 1, 1, true); err != nil {
			return fmt.Errorf("encoding rAC: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CGI from APER format.
func (v *CGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CGI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CGI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CGI")
	}
	bb.EnterComponent("CGI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CGI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CGI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CGI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CGI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CGI{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_rac, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	val_lac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "LAC")
	}
	v.LAC = s00.LAC(val_lac)
	val_ci, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CI")
	}
	v.CI = s00.CI(val_ci)
	if opt_rac {
		val_rac, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "RAC")
		}
		tmp_rac := s00.RAC(val_rac)
		if err := aper.ChargeValue(bb, tmp_rac); err != nil {
			return err
		}
		v.RAC = &tmp_rac
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.CGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CGIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CNTypeRestrictionsItem to APER format.
func (v *CNTypeRestrictionsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CNTypeRestrictionsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.CNType), 1, true); err != nil {
		return fmt.Errorf("encoding cNType: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CNTypeRestrictionsItem from APER format.
func (v *CNTypeRestrictionsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CNTypeRestrictionsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CNTypeRestrictionsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictionsItem")
	}
	bb.EnterComponent("CNTypeRestrictionsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictionsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CNTypeRestrictionsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictionsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CNTypeRestrictionsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CNTypeRestrictionsItem{}
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
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNidentity(val_plmnidentity)
	val_cntype, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "CNType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "CNType")
	}
	v.CNType = s00.CNType(val_cntype)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.CNTypeRestrictionsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CNTypeRestrictionsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CSGIdListItem to APER format.
func (v *CSGIdListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CSGIdListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBitStringAligned(bb, v.CSGId.Bytes, v.CSGId.BitLength, 27, 27, true); err != nil {
		return fmt.Errorf("encoding cSG-Id: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCSGIdListItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CSGIdListItem from APER format.
func (v *CSGIdListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CSGIdListItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CSGIdListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CSGIdListItem")
	}
	bb.EnterComponent("CSGIdListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CSGIdListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CSGIdListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGIdListItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CSGIdListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGIdListItem{}
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
	bsBytes_csgid, bsBitLen_csgid, err := aper.DecodeBitStringAligned(bb, 27, 27, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGId")
	}
	v.CSGId = runtime.BitString{Bytes: bsBytes_csgid, BitLength: bsBitLen_csgid}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.CSGIdListItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CSGIdListItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCSGIdListItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes COUNTvalue to APER format.
func (v *COUNTvalue) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *COUNTvalue) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.PDCPSN), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false); err != nil {
		return fmt.Errorf("encoding pDCP-SN: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HFN), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(1048575), false); err != nil {
		return fmt.Errorf("encoding hFN: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCOUNTvalueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes COUNTvalue from APER format.
func (v *COUNTvalue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes COUNTvalue with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *COUNTvalue) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvalue")
	}
	bb.EnterComponent("COUNTvalue")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvalue")
	}
	padding, err := aper.CaptureFinalBits(bb, "COUNTvalue")
	if err != nil {
		return runtime.WrapDecodePath(err, "COUNTvalue")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *COUNTvalue) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvalue{}
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
	val_pdcpsn, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PDCPSN")
	}
	v.PDCPSN = s00.PDCPSN(val_pdcpsn)
	val_hfn, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(1048575), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HFN")
	}
	v.HFN = s00.HFN(val_hfn)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.COUNTvalueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.COUNTvalueExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCOUNTvalueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes COUNTValueExtended to APER format.
func (v *COUNTValueExtended) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *COUNTValueExtended) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.PDCPSNExtended), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding pDCP-SNExtended: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HFNModified), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(131071), false); err != nil {
		return fmt.Errorf("encoding hFNModified: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCOUNTValueExtendedExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes COUNTValueExtended from APER format.
func (v *COUNTValueExtended) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes COUNTValueExtended with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *COUNTValueExtended) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "COUNTValueExtended")
	}
	bb.EnterComponent("COUNTValueExtended")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "COUNTValueExtended")
	}
	padding, err := aper.CaptureFinalBits(bb, "COUNTValueExtended")
	if err != nil {
		return runtime.WrapDecodePath(err, "COUNTValueExtended")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *COUNTValueExtended) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTValueExtended{}
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
	val_pdcpsnextended, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PDCPSNExtended")
	}
	v.PDCPSNExtended = s00.PDCPSNExtended(val_pdcpsnextended)
	val_hfnmodified, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(131071), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HFNModified")
	}
	v.HFNModified = s00.HFNModified(val_hfnmodified)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.COUNTValueExtendedExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.COUNTValueExtendedExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCOUNTValueExtendedExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes COUNTvaluePDCPSNlength18 to APER format.
func (v *COUNTvaluePDCPSNlength18) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.PDCPSNlength18), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(262143), false); err != nil {
		return fmt.Errorf("encoding pDCP-SNlength18: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HFNforPDCPSNlength18), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16383), false); err != nil {
		return fmt.Errorf("encoding hFNforPDCP-SNlength18: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes COUNTvaluePDCPSNlength18 from APER format.
func (v *COUNTvaluePDCPSNlength18) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes COUNTvaluePDCPSNlength18 with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *COUNTvaluePDCPSNlength18) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
	}
	bb.EnterComponent("COUNTvaluePDCPSNlength18")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
	}
	padding, err := aper.CaptureFinalBits(bb, "COUNTvaluePDCPSNlength18")
	if err != nil {
		return runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *COUNTvaluePDCPSNlength18) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvaluePDCPSNlength18{}
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
	val_pdcpsnlength18, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(262143), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PDCPSNlength18")
	}
	v.PDCPSNlength18 = s00.PDCPSNlength18(val_pdcpsnlength18)
	val_hfnforpdcpsnlength18, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16383), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HFNforPDCPSNlength18")
	}
	v.HFNforPDCPSNlength18 = s00.HFNforPDCPSNlength18(val_hfnforpdcpsnlength18)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.COUNTvaluePDCPSNlength18ExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.COUNTvaluePDCPSNlength18ExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CriticalityDiagnosticsIEItem to APER format.
func (v *CriticalityDiagnosticsIEItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.IECriticality), 3, false); err != nil {
		return fmt.Errorf("encoding iECriticality: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.IEID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding iE-ID: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.TypeOfError), 2, true); err != nil {
		return fmt.Errorf("encoding typeOfError: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CriticalityDiagnosticsIEItem from APER format.
func (v *CriticalityDiagnosticsIEItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CriticalityDiagnosticsIEItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CriticalityDiagnosticsIEItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItem")
	}
	bb.EnterComponent("CriticalityDiagnosticsIEItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsIEItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CriticalityDiagnosticsIEItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEItem{}
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
	val_iecriticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "IECriticality"})
	if err != nil {
		return runtime.WrapDecodePath(err, "IECriticality")
	}
	v.IECriticality = s00.Criticality(val_iecriticality)
	val_ieid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "IEID")
	}
	v.IEID = s00.ProtocolIEID(val_ieid)
	val_typeoferror, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TypeOfError"})
	if err != nil {
		return runtime.WrapDecodePath(err, "TypeOfError")
	}
	v.TypeOfError = s00.TypeOfError(val_typeoferror)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CriticalityDiagnosticsIEItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DAPSRequestInfo to APER format.
func (v *DAPSRequestInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DAPSRequestInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.DAPSIndicator), 1, true); err != nil {
		return fmt.Errorf("encoding dAPSIndicator: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeDAPSRequestInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DAPSRequestInfo from APER format.
func (v *DAPSRequestInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DAPSRequestInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DAPSRequestInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DAPSRequestInfo")
	}
	bb.EnterComponent("DAPSRequestInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSRequestInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "DAPSRequestInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSRequestInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DAPSRequestInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSRequestInfo{}
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
	val_dapsindicator, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DAPSIndicator"})
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSIndicator")
	}
	v.DAPSIndicator = val_dapsindicator
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.DAPSRequestInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.DAPSRequestInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeDAPSRequestInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DAPSResponseInfoItem to APER format.
func (v *DAPSResponseInfoItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DAPSResponseInfoItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := v.DAPSResponseInfo.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dAPSResponseInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DAPSResponseInfoItem from APER format.
func (v *DAPSResponseInfoItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DAPSResponseInfoItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DAPSResponseInfoItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
	}
	bb.EnterComponent("DAPSResponseInfoItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DAPSResponseInfoItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoItem{}
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
	toleranceMark_dapsresponseinfo := bb.EnterComponent("DAPSResponseInfo")
	if err := v.DAPSResponseInfo.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	bb.LeaveComponent(toleranceMark_dapsresponseinfo)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.DAPSResponseInfoItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.DAPSResponseInfoItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DAPSResponseInfo to APER format.
func (v *DAPSResponseInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DAPSResponseInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Dapsresponseindicator), 2, true); err != nil {
		return fmt.Errorf("encoding dapsresponseindicator: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeDAPSResponseInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DAPSResponseInfo from APER format.
func (v *DAPSResponseInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DAPSResponseInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DAPSResponseInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	bb.EnterComponent("DAPSResponseInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "DAPSResponseInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DAPSResponseInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfo{}
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
	val_dapsresponseindicator, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Dapsresponseindicator"})
	if err != nil {
		return runtime.WrapDecodePath(err, "Dapsresponseindicator")
	}
	v.Dapsresponseindicator = val_dapsresponseindicator
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.DAPSResponseInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.DAPSResponseInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeDAPSResponseInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DLCOUNTPDCPSNlength to APER format.
func (v *DLCOUNTPDCPSNlength) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *DLCOUNTPDCPSNlength) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "DLCOUNTPDCPSNlength:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "DLCOUNTPDCPSNlength:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "DLCOUNTPDCPSNlength:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "DLCOUNTPDCPSNlength:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		if v.DLCOUNTValuePDCPSNlength12 == nil {
			return fmt.Errorf("choice alternative dLCOUNTValuePDCP-SNlength12 is nil")
		}
		if err := v.DLCOUNTValuePDCPSNlength12.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding dLCOUNTValuePDCP-SNlength12: %w", err)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		if v.DLCOUNTValuePDCPSNlength15 == nil {
			return fmt.Errorf("choice alternative dLCOUNTValuePDCP-SNlength15 is nil")
		}
		if err := v.DLCOUNTValuePDCPSNlength15.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding dLCOUNTValuePDCP-SNlength15: %w", err)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		if v.DLCOUNTValuePDCPSNlength18 == nil {
			return fmt.Errorf("choice alternative dLCOUNTValuePDCP-SNlength18 is nil")
		}
		if err := v.DLCOUNTValuePDCPSNlength18.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding dLCOUNTValuePDCP-SNlength18: %w", err)
		}
	default:
		return fmt.Errorf("unknown DLCOUNTPDCPSNlength choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes DLCOUNTPDCPSNlength from APER format.
func (v *DLCOUNTPDCPSNlength) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DLCOUNTPDCPSNlength with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DLCOUNTPDCPSNlength) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	bb.EnterComponent("DLCOUNTPDCPSNlength")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	padding, err := aper.CaptureFinalBits(bb, "DLCOUNTPDCPSNlength")
	if err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *DLCOUNTPDCPSNlength) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DLCOUNTPDCPSNlength{}
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
		if err := openExtension.ObserveUnknown(bb); err != nil {
			return err
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		toleranceMark_dlcountvaluepdcpsnlength12 := bb.EnterComponent("DLCOUNTValuePDCPSNlength12")
		var dec_dlcountvaluepdcpsnlength12 COUNTvalue
		if err := dec_dlcountvaluepdcpsnlength12.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "DLCOUNTValuePDCPSNlength12")
		}
		if err := aper.ChargeValue(bb, dec_dlcountvaluepdcpsnlength12); err != nil {
			return err
		}
		v.DLCOUNTValuePDCPSNlength12 = &dec_dlcountvaluepdcpsnlength12
		bb.LeaveComponent(toleranceMark_dlcountvaluepdcpsnlength12)
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		toleranceMark_dlcountvaluepdcpsnlength15 := bb.EnterComponent("DLCOUNTValuePDCPSNlength15")
		var dec_dlcountvaluepdcpsnlength15 COUNTValueExtended
		if err := dec_dlcountvaluepdcpsnlength15.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "DLCOUNTValuePDCPSNlength15")
		}
		if err := aper.ChargeValue(bb, dec_dlcountvaluepdcpsnlength15); err != nil {
			return err
		}
		v.DLCOUNTValuePDCPSNlength15 = &dec_dlcountvaluepdcpsnlength15
		bb.LeaveComponent(toleranceMark_dlcountvaluepdcpsnlength15)
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		toleranceMark_dlcountvaluepdcpsnlength18 := bb.EnterComponent("DLCOUNTValuePDCPSNlength18")
		var dec_dlcountvaluepdcpsnlength18 COUNTvaluePDCPSNlength18
		if err := dec_dlcountvaluepdcpsnlength18.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "DLCOUNTValuePDCPSNlength18")
		}
		if err := aper.ChargeValue(bb, dec_dlcountvaluepdcpsnlength18); err != nil {
			return err
		}
		v.DLCOUNTValuePDCPSNlength18 = &dec_dlcountvaluepdcpsnlength18
		bb.LeaveComponent(toleranceMark_dlcountvaluepdcpsnlength18)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AllocationAndRetentionPriority) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "AllocationAndRetentionPriority", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AllocationAndRetentionPriority", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AllocationAndRetentionPriority) WithoutReplay() AllocationAndRetentionPriority {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AllocationAndRetentionPriority
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToEarlyStatusTransferItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToEarlyStatusTransferItem) WithoutReplay() BearersSubjectToEarlyStatusTransferItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToEarlyStatusTransferItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BluetoothMeasurementConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "BluetoothMeasurementConfiguration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BluetoothMeasurementConfiguration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BluetoothMeasurementConfiguration) WithoutReplay() BluetoothMeasurementConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BluetoothMeasurementConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CGI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CGI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CGI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CGI) WithoutReplay() CGI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CNTypeRestrictionsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CNTypeRestrictionsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CNTypeRestrictionsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CNTypeRestrictionsItem) WithoutReplay() CNTypeRestrictionsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CNTypeRestrictionsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *COUNTValueExtended) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "COUNTValueExtended", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "COUNTValueExtended", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v COUNTValueExtended) WithoutReplay() COUNTValueExtended {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero COUNTValueExtended
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *COUNTvalue) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "COUNTvalue", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "COUNTvalue", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v COUNTvalue) WithoutReplay() COUNTvalue {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero COUNTvalue
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *COUNTvaluePDCPSNlength18) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "COUNTvaluePDCPSNlength18", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "COUNTvaluePDCPSNlength18", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v COUNTvaluePDCPSNlength18) WithoutReplay() COUNTvaluePDCPSNlength18 {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero COUNTvaluePDCPSNlength18
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CSGIdListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CSGIdListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CSGIdListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CSGIdListItem) WithoutReplay() CSGIdListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CSGIdListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Cause) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "Cause", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Cause", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Cause) WithoutReplay() Cause {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Cause
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Cdma2000OneXSRVCCInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "Cdma2000OneXSRVCCInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Cdma2000OneXSRVCCInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Cdma2000OneXSRVCCInfo) WithoutReplay() Cdma2000OneXSRVCCInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Cdma2000OneXSRVCCInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellType) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CellType", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellType", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellType) WithoutReplay() CellType {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellType
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnosticsIEItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnosticsIEItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CriticalityDiagnosticsIEItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnosticsIEItem) WithoutReplay() CriticalityDiagnosticsIEItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CriticalityDiagnosticsIEItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DAPSRequestInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "DAPSRequestInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DAPSRequestInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DAPSRequestInfo) WithoutReplay() DAPSRequestInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DAPSRequestInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DAPSResponseInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "DAPSResponseInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DAPSResponseInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DAPSResponseInfo) WithoutReplay() DAPSResponseInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DAPSResponseInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DAPSResponseInfoItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "DAPSResponseInfoItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DAPSResponseInfoItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DAPSResponseInfoItem) WithoutReplay() DAPSResponseInfoItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DAPSResponseInfoItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DLCOUNTPDCPSNlength) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "DLCOUNTPDCPSNlength", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DLCOUNTPDCPSNlength", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DLCOUNTPDCPSNlength) WithoutReplay() DLCOUNTPDCPSNlength {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DLCOUNTPDCPSNlength
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AllocationAndRetentionPriority) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AllocationAndRetentionPriority) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AllocationAndRetentionPriority) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *BearersSubjectToEarlyStatusTransferItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *BearersSubjectToEarlyStatusTransferItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *BearersSubjectToEarlyStatusTransferItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *BluetoothMeasurementConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *BluetoothMeasurementConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *BluetoothMeasurementConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CGI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CGI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CNTypeRestrictionsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CNTypeRestrictionsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CNTypeRestrictionsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *COUNTValueExtended) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *COUNTValueExtended) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *COUNTValueExtended) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *COUNTvalue) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *COUNTvalue) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *COUNTvalue) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *COUNTvaluePDCPSNlength18) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *COUNTvaluePDCPSNlength18) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *COUNTvaluePDCPSNlength18) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CSGIdListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CSGIdListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CSGIdListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *Cdma2000OneXSRVCCInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *Cdma2000OneXSRVCCInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *Cdma2000OneXSRVCCInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellType) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellType) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellType) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CriticalityDiagnosticsIEItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CriticalityDiagnosticsIEItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CriticalityDiagnosticsIEItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DAPSRequestInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DAPSRequestInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DAPSRequestInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DAPSResponseInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DAPSResponseInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DAPSResponseInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DAPSResponseInfoItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DAPSResponseInfoItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DAPSResponseInfoItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *AllocationAndRetentionPriority) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AllocationAndRetentionPriority")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AllocationAndRetentionPriority) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AllocationAndRetentionPriority")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAllocationAndRetentionPriority(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AllocationAndRetentionPriority")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AllocationAndRetentionPriority")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AllocationAndRetentionPriority) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AllocationAndRetentionPriority")
}
func (v *AllocationAndRetentionPriority) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AllocationAndRetentionPriority")
}
func (v *AllocationAndRetentionPriority) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAllocationAndRetentionPriority(v, &s)
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
func (v *AllocationAndRetentionPriority) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AllocationAndRetentionPriority) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BearersSubjectToEarlyStatusTransferItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToEarlyStatusTransferItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v, &s)
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
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BluetoothMeasurementConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BluetoothMeasurementConfiguration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BluetoothMeasurementConfiguration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasurementConfiguration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBluetoothMeasurementConfiguration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BluetoothMeasurementConfiguration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BluetoothMeasurementConfiguration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BluetoothMeasurementConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BluetoothMeasurementConfiguration")
}
func (v *BluetoothMeasurementConfiguration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BluetoothMeasurementConfiguration")
}
func (v *BluetoothMeasurementConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBluetoothMeasurementConfiguration(v, &s)
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
func (v *BluetoothMeasurementConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BluetoothMeasurementConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CGI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CGI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CGI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CGI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCGI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CGI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CGI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CGI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CGI")
}
func (v *CGI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CGI")
}
func (v *CGI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCGI(v, &s)
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
func (v *CGI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CGI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CNTypeRestrictionsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CNTypeRestrictionsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CNTypeRestrictionsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCNTypeRestrictionsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CNTypeRestrictionsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CNTypeRestrictionsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CNTypeRestrictionsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CNTypeRestrictionsItem")
}
func (v *CNTypeRestrictionsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CNTypeRestrictionsItem")
}
func (v *CNTypeRestrictionsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCNTypeRestrictionsItem(v, &s)
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
func (v *CNTypeRestrictionsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CNTypeRestrictionsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *COUNTValueExtended) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "COUNTValueExtended")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *COUNTValueExtended) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "COUNTValueExtended")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCOUNTValueExtended(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "COUNTValueExtended")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "COUNTValueExtended")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *COUNTValueExtended) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "COUNTValueExtended")
}
func (v *COUNTValueExtended) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "COUNTValueExtended")
}
func (v *COUNTValueExtended) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCOUNTValueExtended(v, &s)
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
func (v *COUNTValueExtended) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *COUNTValueExtended) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *COUNTvalue) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "COUNTvalue")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *COUNTvalue) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "COUNTvalue")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCOUNTvalue(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "COUNTvalue")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "COUNTvalue")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *COUNTvalue) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "COUNTvalue")
}
func (v *COUNTvalue) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "COUNTvalue")
}
func (v *COUNTvalue) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCOUNTvalue(v, &s)
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
func (v *COUNTvalue) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *COUNTvalue) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *COUNTvaluePDCPSNlength18) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "COUNTvaluePDCPSNlength18")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCOUNTvaluePDCPSNlength18(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "COUNTvaluePDCPSNlength18")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCOUNTvaluePDCPSNlength18(v, &s)
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
func (v *COUNTvaluePDCPSNlength18) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CSGIdListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CSGIdListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CSGIdListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CSGIdListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCSGIdListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CSGIdListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CSGIdListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CSGIdListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CSGIdListItem")
}
func (v *CSGIdListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CSGIdListItem")
}
func (v *CSGIdListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCSGIdListItem(v, &s)
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
func (v *CSGIdListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CSGIdListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *Cause) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Cause")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Cause) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Cause")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCause(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Cause")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Cause")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Cause) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Cause")
}
func (v *Cause) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Cause")
}
func (v *Cause) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCause(v, &s)
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
func (v *Cause) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Cause) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *Cdma2000OneXSRVCCInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Cdma2000OneXSRVCCInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCdma2000OneXSRVCCInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Cdma2000OneXSRVCCInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCdma2000OneXSRVCCInfo(v, &s)
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
func (v *Cdma2000OneXSRVCCInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellType) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellType")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellType) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellType")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellType(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellType")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellType")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellType) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellType")
}
func (v *CellType) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellType")
}
func (v *CellType) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellType(v, &s)
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
func (v *CellType) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellType) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CriticalityDiagnosticsIEItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCriticalityDiagnosticsIEItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CriticalityDiagnosticsIEItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCriticalityDiagnosticsIEItem(v, &s)
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
func (v *CriticalityDiagnosticsIEItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DAPSRequestInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DAPSRequestInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DAPSRequestInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DAPSRequestInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDAPSRequestInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DAPSRequestInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DAPSRequestInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DAPSRequestInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DAPSRequestInfo")
}
func (v *DAPSRequestInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DAPSRequestInfo")
}
func (v *DAPSRequestInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDAPSRequestInfo(v, &s)
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
func (v *DAPSRequestInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DAPSRequestInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DAPSResponseInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DAPSResponseInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DAPSResponseInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDAPSResponseInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DAPSResponseInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DAPSResponseInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DAPSResponseInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DAPSResponseInfo")
}
func (v *DAPSResponseInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DAPSResponseInfo")
}
func (v *DAPSResponseInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDAPSResponseInfo(v, &s)
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
func (v *DAPSResponseInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DAPSResponseInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DAPSResponseInfoItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DAPSResponseInfoItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DAPSResponseInfoItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfoItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDAPSResponseInfoItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DAPSResponseInfoItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DAPSResponseInfoItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DAPSResponseInfoItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DAPSResponseInfoItem")
}
func (v *DAPSResponseInfoItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DAPSResponseInfoItem")
}
func (v *DAPSResponseInfoItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDAPSResponseInfoItem(v, &s)
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
func (v *DAPSResponseInfoItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DAPSResponseInfoItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DLCOUNTPDCPSNlength) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DLCOUNTPDCPSNlength")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DLCOUNTPDCPSNlength) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DLCOUNTPDCPSNlength")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDLCOUNTPDCPSNlength(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DLCOUNTPDCPSNlength")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DLCOUNTPDCPSNlength")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DLCOUNTPDCPSNlength) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DLCOUNTPDCPSNlength")
}
func (v *DLCOUNTPDCPSNlength) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DLCOUNTPDCPSNlength")
}
func (v *DLCOUNTPDCPSNlength) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDLCOUNTPDCPSNlength(v, &s)
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
func (v *DLCOUNTPDCPSNlength) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DLCOUNTPDCPSNlength) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AllocationAndRetentionPriority) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AllocationAndRetentionPriority")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AllocationAndRetentionPriority
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAllocationAndRetentionPriority(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AllocationAndRetentionPriority{}
		return report, aper.OperationError(err, "AllocationAndRetentionPriority")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AllocationAndRetentionPriority")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToEarlyStatusTransferItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToEarlyStatusTransferItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToEarlyStatusTransferItem{}
		return report, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToEarlyStatusTransferItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BluetoothMeasurementConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasurementConfiguration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BluetoothMeasurementConfiguration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBluetoothMeasurementConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BluetoothMeasurementConfiguration{}
		return report, aper.OperationError(err, "BluetoothMeasurementConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BluetoothMeasurementConfiguration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CGI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CGI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CGI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCGI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CGI{}
		return report, aper.OperationError(err, "CGI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CGI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CNTypeRestrictionsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CNTypeRestrictionsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCNTypeRestrictionsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CNTypeRestrictionsItem{}
		return report, aper.OperationError(err, "CNTypeRestrictionsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CNTypeRestrictionsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *COUNTValueExtended) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "COUNTValueExtended")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded COUNTValueExtended
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCOUNTValueExtended(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = COUNTValueExtended{}
		return report, aper.OperationError(err, "COUNTValueExtended")
	}
	*v = decoded
	return report, aper.OperationError(nil, "COUNTValueExtended")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *COUNTvalue) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "COUNTvalue")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded COUNTvalue
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCOUNTvalue(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = COUNTvalue{}
		return report, aper.OperationError(err, "COUNTvalue")
	}
	*v = decoded
	return report, aper.OperationError(nil, "COUNTvalue")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *COUNTvaluePDCPSNlength18) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "COUNTvaluePDCPSNlength18")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded COUNTvaluePDCPSNlength18
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCOUNTvaluePDCPSNlength18(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = COUNTvaluePDCPSNlength18{}
		return report, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
	}
	*v = decoded
	return report, aper.OperationError(nil, "COUNTvaluePDCPSNlength18")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CSGIdListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CSGIdListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CSGIdListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCSGIdListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CSGIdListItem{}
		return report, aper.OperationError(err, "CSGIdListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CSGIdListItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *Cause) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Cause")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Cause
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCause(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Cause{}
		return report, aper.OperationError(err, "Cause")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Cause")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *Cdma2000OneXSRVCCInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Cdma2000OneXSRVCCInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Cdma2000OneXSRVCCInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCdma2000OneXSRVCCInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Cdma2000OneXSRVCCInfo{}
		return report, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Cdma2000OneXSRVCCInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellType) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellType")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellType
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellType(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellType{}
		return report, aper.OperationError(err, "CellType")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellType")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CriticalityDiagnosticsIEItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CriticalityDiagnosticsIEItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCriticalityDiagnosticsIEItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CriticalityDiagnosticsIEItem{}
		return report, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CriticalityDiagnosticsIEItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DAPSRequestInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DAPSRequestInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DAPSRequestInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDAPSRequestInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DAPSRequestInfo{}
		return report, aper.OperationError(err, "DAPSRequestInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DAPSRequestInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DAPSResponseInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DAPSResponseInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDAPSResponseInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DAPSResponseInfo{}
		return report, aper.OperationError(err, "DAPSResponseInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DAPSResponseInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DAPSResponseInfoItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfoItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DAPSResponseInfoItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDAPSResponseInfoItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DAPSResponseInfoItem{}
		return report, aper.OperationError(err, "DAPSResponseInfoItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DAPSResponseInfoItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DLCOUNTPDCPSNlength) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DLCOUNTPDCPSNlength")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DLCOUNTPDCPSNlength
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDLCOUNTPDCPSNlength(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DLCOUNTPDCPSNlength{}
		return report, aper.OperationError(err, "DLCOUNTPDCPSNlength")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DLCOUNTPDCPSNlength")
}

// CSGMembershipInfo represents the ASN.1 type CSGMembershipInfo (SEQUENCE).
type CSGMembershipInfo struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	CSGMembershipStatus s00.CSGMembershipStatus                 `asn1:"tag:0,context,implicit"`
	CSGId               s00.CSGId                               `asn1:"tag:1,context,implicit"`
	CellAccessMode      *s00.CellAccessMode                     `asn1:"tag:2,context,implicit,optional" json:"CellAccessMode,omitempty"`
	PLMNidentity        *s00.PLMNidentity                       `asn1:"tag:3,context,implicit,optional" json:"PLMNidentity,omitempty"`
	IEExtensions        s07.CSGMembershipInfoExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                    `asn1:"-" json:"-"`
	extCount            int64                                   `asn1:"-" json:"-"`
	extPresent          []bool                                  `asn1:"-" json:"-"`
	extData             [][]byte                                `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// MarshalAPER encodes CSGMembershipInfo to APER format.
func (v *CSGMembershipInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CSGMembershipInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, v.CellAccessMode != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.PLMNidentity != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.CSGMembershipStatus), 2, false); err != nil {
		return fmt.Errorf("encoding cSGMembershipStatus: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.CSGId.Bytes, v.CSGId.BitLength, 27, 27, true); err != nil {
		return fmt.Errorf("encoding cSG-Id: %w", err)
	}
	if v.CellAccessMode != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.CellAccessMode), 1, true); err != nil {
			return fmt.Errorf("encoding cellAccessMode: %w", err)
		}
	}
	if v.PLMNidentity != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.PLMNidentity), 3, 3, true); err != nil {
			return fmt.Errorf("encoding pLMNidentity: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCSGMembershipInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CSGMembershipInfo from APER format.
func (v *CSGMembershipInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CSGMembershipInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CSGMembershipInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	bb.EnterComponent("CSGMembershipInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "CSGMembershipInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CSGMembershipInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGMembershipInfo{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_cellaccessmode, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_plmnidentity, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_csgmembershipstatus, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CSGMembershipStatus"})
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipStatus")
	}
	v.CSGMembershipStatus = s00.CSGMembershipStatus(val_csgmembershipstatus)
	bsBytes_csgid, bsBitLen_csgid, err := aper.DecodeBitStringAligned(bb, 27, 27, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGId")
	}
	v.CSGId = runtime.BitString{Bytes: bsBytes_csgid, BitLength: bsBitLen_csgid}
	if opt_cellaccessmode {
		val_cellaccessmode, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellAccessMode"})
		if err != nil {
			return runtime.WrapDecodePath(err, "CellAccessMode")
		}
		tmp_cellaccessmode := s00.CellAccessMode(val_cellaccessmode)
		if err := aper.ChargeValue(bb, tmp_cellaccessmode); err != nil {
			return err
		}
		v.CellAccessMode = (*s00.CellAccessMode)(bb.OwnInt64(int64(tmp_cellaccessmode)))

	}
	if opt_plmnidentity {
		val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PLMNidentity")
		}
		tmp_plmnidentity := s00.PLMNidentity(val_plmnidentity)
		if err := aper.ChargeValue(bb, tmp_plmnidentity); err != nil {
			return err
		}
		v.PLMNidentity = &tmp_plmnidentity
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.CSGMembershipInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CSGMembershipInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeCSGMembershipInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CSGMembershipInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CSGMembershipInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CSGMembershipInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CSGMembershipInfo) WithoutReplay() CSGMembershipInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CSGMembershipInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CSGMembershipInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CSGMembershipInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CSGMembershipInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CSGMembershipInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CSGMembershipInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CSGMembershipInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CSGMembershipInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCSGMembershipInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CSGMembershipInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CSGMembershipInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CSGMembershipInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CSGMembershipInfo")
}
func (v *CSGMembershipInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CSGMembershipInfo")
}
func (v *CSGMembershipInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCSGMembershipInfo(v, &s)
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
func (v *CSGMembershipInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CSGMembershipInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CSGMembershipInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CSGMembershipInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CSGMembershipInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCSGMembershipInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CSGMembershipInfo{}
		return report, aper.OperationError(err, "CSGMembershipInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CSGMembershipInfo")
}

type CandidatePCIList = []CandidatePCI

// CandidatePCI represents the ASN.1 type CandidatePCI (SEQUENCE).
type CandidatePCI struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	PCI              int64                  `asn1:"tag:0,context,implicit"`
	EARFCN           []byte                 `asn1:"tag:1,context,implicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type CellsToActivateList = []CellsToActivateListItem

// CellsToActivateListItem represents the ASN.1 type CellsToActivateList-Item (SEQUENCE).
type CellsToActivateListItem struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	CellID           []byte                 `asn1:"tag:0,context,implicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type ActivatedCellsList = []ActivatedCellsListItem

// ActivatedCellsListItem represents the ASN.1 type ActivatedCellsList-Item (SEQUENCE).
type ActivatedCellsListItem struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	CellID           []byte                 `asn1:"tag:0,context,implicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes CandidatePCI to APER format.
func (v *CandidatePCI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CandidatePCI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.PCI), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding pCI: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, v.EARFCN, 0, 0, false); err != nil {
		return fmt.Errorf("encoding eARFCN: %w", err)
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

// UnmarshalAPER decodes CandidatePCI from APER format.
func (v *CandidatePCI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CandidatePCI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CandidatePCI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	bb.EnterComponent("CandidatePCI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CandidatePCI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CandidatePCI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CandidatePCI{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(503), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
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

// MarshalAPER encodes CellsToActivateListItem to APER format.
func (v *CellsToActivateListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellsToActivateListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes CellsToActivateListItem from APER format.
func (v *CellsToActivateListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellsToActivateListItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellsToActivateListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	bb.EnterComponent("CellsToActivateListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellsToActivateListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellsToActivateListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellsToActivateListItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
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

// MarshalAPER encodes ActivatedCellsListItem to APER format.
func (v *ActivatedCellsListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ActivatedCellsListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes ActivatedCellsListItem from APER format.
func (v *ActivatedCellsListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ActivatedCellsListItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ActivatedCellsListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	bb.EnterComponent("ActivatedCellsListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ActivatedCellsListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ActivatedCellsListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ActivatedCellsListItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
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
func (v *ActivatedCellsListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "ActivatedCellsListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ActivatedCellsListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ActivatedCellsListItem) WithoutReplay() ActivatedCellsListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ActivatedCellsListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CandidatePCI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CandidatePCI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CandidatePCI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CandidatePCI) WithoutReplay() CandidatePCI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CandidatePCI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellsToActivateListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CellsToActivateListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellsToActivateListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellsToActivateListItem) WithoutReplay() CellsToActivateListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellsToActivateListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ActivatedCellsListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ActivatedCellsListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ActivatedCellsListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CandidatePCI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CandidatePCI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CandidatePCI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellsToActivateListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellsToActivateListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellsToActivateListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ActivatedCellsListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ActivatedCellsListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ActivatedCellsListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APActivatedCellsListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ActivatedCellsListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ActivatedCellsListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ActivatedCellsListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ActivatedCellsListItem")
}
func (v *ActivatedCellsListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ActivatedCellsListItem")
}
func (v *ActivatedCellsListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APActivatedCellsListItem(v, &s)
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
func (v *ActivatedCellsListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ActivatedCellsListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CandidatePCI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CandidatePCI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CandidatePCI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CandidatePCI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCandidatePCI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CandidatePCI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CandidatePCI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CandidatePCI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CandidatePCI")
}
func (v *CandidatePCI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CandidatePCI")
}
func (v *CandidatePCI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCandidatePCI(v, &s)
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
func (v *CandidatePCI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CandidatePCI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellsToActivateListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellsToActivateListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellsToActivateListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellsToActivateListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellsToActivateListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellsToActivateListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellsToActivateListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellsToActivateListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellsToActivateListItem")
}
func (v *CellsToActivateListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellsToActivateListItem")
}
func (v *CellsToActivateListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellsToActivateListItem(v, &s)
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
func (v *CellsToActivateListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellsToActivateListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ActivatedCellsListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ActivatedCellsListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APActivatedCellsListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ActivatedCellsListItem{}
		return report, aper.OperationError(err, "ActivatedCellsListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ActivatedCellsListItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CandidatePCI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CandidatePCI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CandidatePCI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCandidatePCI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CandidatePCI{}
		return report, aper.OperationError(err, "CandidatePCI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CandidatePCI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellsToActivateListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellsToActivateListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellsToActivateListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellsToActivateListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellsToActivateListItem{}
		return report, aper.OperationError(err, "CellsToActivateListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellsToActivateListItem")
}

type BearersSubjectToStatusTransferItemExtIEsValue struct {
	id                                         s00.ProtocolIEID
	received                                   aper.WireSpan
	replay                                     aper.Snapshot
	opaque                                     aper.OpaqueOpenType
	isOpaque                                   bool
	rowULCOUNTValueExtended                    *COUNTValueExtended
	rowDLCOUNTValueExtended                    *COUNTValueExtended
	rowReceiveStatusOfULPDCPSDUsExtended       *s00.ReceiveStatusOfULPDCPSDUsExtended
	rowULCOUNTValuePDCPSNlength18              *COUNTvaluePDCPSNlength18
	rowDLCOUNTValuePDCPSNlength18              *COUNTvaluePDCPSNlength18
	rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 *s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
}

func (v BearersSubjectToStatusTransferItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(179):
		return v.rowULCOUNTValueExtended != nil
	case s00.ProtocolIEID(180):
		return v.rowDLCOUNTValueExtended != nil
	case s00.ProtocolIEID(181):
		return v.rowReceiveStatusOfULPDCPSDUsExtended != nil
	case s00.ProtocolIEID(217):
		return v.rowULCOUNTValuePDCPSNlength18 != nil
	case s00.ProtocolIEID(218):
		return v.rowDLCOUNTValuePDCPSNlength18 != nil
	case s00.ProtocolIEID(219):
		return v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 != nil
	}
	return false
}

// Opaque returns the retained opaque open value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether the opaque alternative is selected.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToStatusTransferItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs"}}
}
func (BearersSubjectToStatusTransferItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(179):
		return aper.UnknownSelector
	case s00.ProtocolIEID(180):
		return aper.UnknownSelector
	case s00.ProtocolIEID(181):
		return aper.UnknownSelector
	case s00.ProtocolIEID(217):
		return aper.UnknownSelector
	case s00.ProtocolIEID(218):
		return aper.UnknownSelector
	case s00.ProtocolIEID(219):
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

// AsULCOUNTValueExtended returns the selected ULCOUNTValueExtended value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsULCOUNTValueExtended() (*COUNTValueExtended, bool) {
	if v == nil || v.id != s00.ProtocolIEID(179) || v.rowULCOUNTValueExtended == nil {
		return nil, false
	}
	return v.rowULCOUNTValueExtended, true
}

// AsDLCOUNTValueExtended returns the selected DLCOUNTValueExtended value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsDLCOUNTValueExtended() (*COUNTValueExtended, bool) {
	if v == nil || v.id != s00.ProtocolIEID(180) || v.rowDLCOUNTValueExtended == nil {
		return nil, false
	}
	return v.rowDLCOUNTValueExtended, true
}

// AsReceiveStatusOfULPDCPSDUsExtended returns the selected ReceiveStatusOfULPDCPSDUsExtended value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsReceiveStatusOfULPDCPSDUsExtended() (*s00.ReceiveStatusOfULPDCPSDUsExtended, bool) {
	if v == nil || v.id != s00.ProtocolIEID(181) || v.rowReceiveStatusOfULPDCPSDUsExtended == nil {
		return nil, false
	}
	return v.rowReceiveStatusOfULPDCPSDUsExtended, true
}

// AsULCOUNTValuePDCPSNlength18 returns the selected ULCOUNTValuePDCPSNlength18 value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsULCOUNTValuePDCPSNlength18() (*COUNTvaluePDCPSNlength18, bool) {
	if v == nil || v.id != s00.ProtocolIEID(217) || v.rowULCOUNTValuePDCPSNlength18 == nil {
		return nil, false
	}
	return v.rowULCOUNTValuePDCPSNlength18, true
}

// AsDLCOUNTValuePDCPSNlength18 returns the selected DLCOUNTValuePDCPSNlength18 value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsDLCOUNTValuePDCPSNlength18() (*COUNTvaluePDCPSNlength18, bool) {
	if v == nil || v.id != s00.ProtocolIEID(218) || v.rowDLCOUNTValuePDCPSNlength18 == nil {
		return nil, false
	}
	return v.rowDLCOUNTValuePDCPSNlength18, true
}

// AsReceiveStatusOfULPDCPSDUsPDCPSNlength18 returns the selected ReceiveStatusOfULPDCPSDUsPDCPSNlength18 value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsReceiveStatusOfULPDCPSDUsPDCPSNlength18() (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, bool) {
	if v == nil || v.id != s00.ProtocolIEID(219) || v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil {
		return nil, false
	}
	return v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, true
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemExtIEsValue, error) {
	out := BearersSubjectToStatusTransferItemExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(179):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTValueExtended
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ULCOUNTValueExtended:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTValueExtended")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowULCOUNTValueExtended = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(180):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTValueExtended
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "DLCOUNTValueExtended:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTValueExtended")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowDLCOUNTValueExtended = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(181):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ReceiveStatusOfULPDCPSDUsExtended, error) {
			var v struct {
				Value s00.ReceiveStatusOfULPDCPSDUsExtended
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 1, 16384, true)
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
		out.rowReceiveStatusOfULPDCPSDUsExtended = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(217):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTvaluePDCPSNlength18
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ULCOUNTValuePDCPSNlength18:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTvaluePDCPSNlength18")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowULCOUNTValuePDCPSNlength18 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(218):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTvaluePDCPSNlength18
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "DLCOUNTValuePDCPSNlength18:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTvaluePDCPSNlength18")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowDLCOUNTValuePDCPSNlength18 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(219):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, error) {
			var v struct {
				Value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 1, 131072, true)
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
		out.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 = &value
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
func (v BearersSubjectToStatusTransferItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(179):
		if v.rowULCOUNTValueExtended == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValueExtended:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowULCOUNTValueExtended.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(180):
		if v.rowDLCOUNTValueExtended == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValueExtended:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowDLCOUNTValueExtended.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(181):
		if v.rowReceiveStatusOfULPDCPSDUsExtended == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsExtended:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ReceiveStatusOfULPDCPSDUsExtended, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.ReceiveStatusOfULPDCPSDUsExtended
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 1, 16384, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowReceiveStatusOfULPDCPSDUsExtended, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(217):
		if v.rowULCOUNTValuePDCPSNlength18 == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValuePDCP-SNlength18:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowULCOUNTValuePDCPSNlength18.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(218):
		if v.rowDLCOUNTValuePDCPSNlength18 == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValuePDCP-SNlength18:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowDLCOUNTValuePDCPSNlength18.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(219):
		if v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 1, 131072, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToStatusTransferItemExtIEsValue:", v.id)
	}
}

type DAPSResponseInfoListIEValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowDAPSResponseInfoItem *DAPSResponseInfoItem
}

func (v DAPSResponseInfoListIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(319):
		return v.rowDAPSResponseInfoItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of DAPSResponseInfoListIEValue and reports whether the opaque alternative is selected.
func (v *DAPSResponseInfoListIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (DAPSResponseInfoListIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoListIEs"}}
}
func (DAPSResponseInfoListIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(319):
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

// AsDAPSResponseInfoItem returns the selected DAPSResponseInfoItem value of DAPSResponseInfoListIEValue and reports whether that alternative is active.
func (v *DAPSResponseInfoListIEValue) AsDAPSResponseInfoItem() (*DAPSResponseInfoItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(319) || v.rowDAPSResponseInfoItem == nil {
		return nil, false
	}
	return v.rowDAPSResponseInfoItem, true
}
func (v DAPSResponseInfoListIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (DAPSResponseInfoListIEValue, error) {
	out := DAPSResponseInfoListIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(319):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value DAPSResponseInfoItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "DAPSResponseInfoItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DAPSResponseInfoItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowDAPSResponseInfoItem = &value
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
func (v DAPSResponseInfoListIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v DAPSResponseInfoListIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(319):
		if v.rowDAPSResponseInfoItem == nil {
			return nil, fmt.Errorf("%s missing value", "DAPSResponseInfoListIEs.id-DAPSResponseInfoItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowDAPSResponseInfoItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "DAPSResponseInfoListIEValue:", v.id)
	}
}

// preferredSequenceTail chooses the shortest extension bitmap containing all
// semantic additions. X.691 (02/2021) §19.8 defines its index and length.
func BridgePreferredSequenceTail(present []bool, data [][]byte) (int64, bool) {
	var last int64
	found := false
	for i, set := range present {
		if set {
			last = int64(i)
			found = true
		}
	}
	for i, contents := range data {
		if contents != nil {
			last = int64(i)
			found = true
		}
	}
	return last, found
}
func BridgeReceivedFormAt(present bool, original aper.WireSpan, path aper.Path, location aper.Location, complete interface{ Bits() (uint8, uint8) }) aper.ReceivedForm {
	location.Path = path
	var padding []aper.PaddingSpan
	if location.HasWireLocation && len(location.Spans) != 0 {
		last := location.Spans[len(location.Spans)-1]
		value, count := complete.Bits()
		width, borrow := bits.Sub64(last.End, last.Start, 0)
		if count != 0 && borrow == 0 && uint64(count) <= width {
			start, borrow := bits.Sub64(last.End, uint64(count), 0)
			if borrow == 0 {
				padding = []aper.PaddingSpan{{Span: aper.BitSpan{Start: start, End: last.End}, Value: value, Width: count}}
			}
		}
	}
	return aper.NewReceivedSpanForm(present, original, location, padding)
}

type BearersSubjectToStatusTransferItemExtIETable struct{}

func BearersSubjectToStatusTransferItemExtIEs() BearersSubjectToStatusTransferItemExtIETable {
	return BearersSubjectToStatusTransferItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToStatusTransferItemExtIETable.
func (BearersSubjectToStatusTransferItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToStatusTransferItemExtIETable.
func (BearersSubjectToStatusTransferItemExtIETable) Table() s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable {
	return func() s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable {
		sealed := s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable{}
		*s00.BridgeBearersSubjectToStatusTransferItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (BearersSubjectToStatusTransferItemExtIETable) infoULCOUNTValueExtended() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(179), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTValueExtended"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ULCOUNTValueExtended"}}}
}

// ULCOUNTValueExtended returns the typed binding for the ULCOUNTValueExtended row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ULCOUNTValueExtended() BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding{info: t.infoULCOUNTValueExtended(), codec: COUNTValueExtendedValueCodec{path: "COUNTValueExtended",
		decode: func(data []byte, options aper.DecodeState) (COUNTValueExtended, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty COUNTValueExtended
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("COUNTValueExtended")
			var zero BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(179), raw)
			if err != nil {
				var empty COUNTValueExtended
				return empty, runtime.WrapDecodePath(err, "COUNTValueExtended")
			}
			value, ok := decoded.AsULCOUNTValueExtended()
			if !ok {
				var empty COUNTValueExtended
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValueExtended: no selected value")
			}
			return *value, nil
		},
		encode: func(value COUNTValueExtended, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(179), rowULCOUNTValueExtended: &value}).encodeFresh(fresh, budget)
		}, capture: func(v COUNTValueExtended, options aper.DecodeState) (COUNTValueExtended, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCOUNTValueExtended(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v COUNTValueExtended, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCOUNTValueExtended(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTValueExtended"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value COUNTValueExtended) BearersSubjectToStatusTransferItemExtIEsValue {
		return BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(179), rowULCOUNTValueExtended: &value}
	}, get: func(value *BearersSubjectToStatusTransferItemExtIEsValue) (*COUNTValueExtended, bool) {
		return value.AsULCOUNTValueExtended()
	}}
}
func (BearersSubjectToStatusTransferItemExtIETable) infoDLCOUNTValueExtended() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(180), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTValueExtended"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-DLCOUNTValueExtended"}}}
}

// DLCOUNTValueExtended returns the typed binding for the DLCOUNTValueExtended row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) DLCOUNTValueExtended() BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding{info: t.infoDLCOUNTValueExtended(), codec: COUNTValueExtendedValueCodec{path: "COUNTValueExtended",
		decode: func(data []byte, options aper.DecodeState) (COUNTValueExtended, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty COUNTValueExtended
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("COUNTValueExtended")
			var zero BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(180), raw)
			if err != nil {
				var empty COUNTValueExtended
				return empty, runtime.WrapDecodePath(err, "COUNTValueExtended")
			}
			value, ok := decoded.AsDLCOUNTValueExtended()
			if !ok {
				var empty COUNTValueExtended
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValueExtended: no selected value")
			}
			return *value, nil
		},
		encode: func(value COUNTValueExtended, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(180), rowDLCOUNTValueExtended: &value}).encodeFresh(fresh, budget)
		}, capture: func(v COUNTValueExtended, options aper.DecodeState) (COUNTValueExtended, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCOUNTValueExtended(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v COUNTValueExtended, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCOUNTValueExtended(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTValueExtended"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value COUNTValueExtended) BearersSubjectToStatusTransferItemExtIEsValue {
		return BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(180), rowDLCOUNTValueExtended: &value}
	}, get: func(value *BearersSubjectToStatusTransferItemExtIEsValue) (*COUNTValueExtended, bool) {
		return value.AsDLCOUNTValueExtended()
	}}
}
func (BearersSubjectToStatusTransferItemExtIETable) infoReceiveStatusOfULPDCPSDUsExtended() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(181), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ReceiveStatusOfULPDCPSDUsExtended"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ReceiveStatusOfULPDCPSDUsExtended"}}}
}

// ReceiveStatusOfULPDCPSDUsExtended returns the typed binding for the ReceiveStatusOfULPDCPSDUsExtended row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ReceiveStatusOfULPDCPSDUsExtended() BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding{info: t.infoReceiveStatusOfULPDCPSDUsExtended(), codec: func() s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec {
		sealed := s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec{}
		*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldPath(&sealed) = "ReceiveStatusOfULPDCPSDUsExtended"
		*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsExtended, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ReceiveStatusOfULPDCPSDUsExtended
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ReceiveStatusOfULPDCPSDUsExtended")
			var zero BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(181), raw)
			if err != nil {
				var empty s00.ReceiveStatusOfULPDCPSDUsExtended
				return empty, runtime.WrapDecodePath(err, "ReceiveStatusOfULPDCPSDUsExtended")
			}
			value, ok := decoded.AsReceiveStatusOfULPDCPSDUsExtended()
			if !ok {
				var empty s00.ReceiveStatusOfULPDCPSDUsExtended
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsExtended: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldEncode(&sealed) = func(value s00.ReceiveStatusOfULPDCPSDUsExtended, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(181), rowReceiveStatusOfULPDCPSDUsExtended: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldCapture(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsExtended, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsExtended, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsExtended(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldCompare(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsExtended, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APReceiveStatusOfULPDCPSDUsExtended(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReceiveStatusOfULPDCPSDUsExtended"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ReceiveStatusOfULPDCPSDUsExtended) BearersSubjectToStatusTransferItemExtIEsValue {
			return BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(181), rowReceiveStatusOfULPDCPSDUsExtended: &value}
		}, get: func(value *BearersSubjectToStatusTransferItemExtIEsValue) (*s00.ReceiveStatusOfULPDCPSDUsExtended, bool) {
			return value.AsReceiveStatusOfULPDCPSDUsExtended()
		}}
}
func (BearersSubjectToStatusTransferItemExtIETable) infoULCOUNTValuePDCPSNlength18() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(217), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvaluePDCP-SNlength18"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ULCOUNTValuePDCP-SNlength18"}}}
}

// ULCOUNTValuePDCPSNlength18 returns the typed binding for the ULCOUNTValuePDCPSNlength18 row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ULCOUNTValuePDCPSNlength18() BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding{info: t.infoULCOUNTValuePDCPSNlength18(), codec: COUNTvaluePDCPSNlength18ValueCodec{path: "COUNTvaluePDCPSNlength18",
		decode: func(data []byte, options aper.DecodeState) (COUNTvaluePDCPSNlength18, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty COUNTvaluePDCPSNlength18
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("COUNTvaluePDCPSNlength18")
			var zero BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(217), raw)
			if err != nil {
				var empty COUNTvaluePDCPSNlength18
				return empty, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
			}
			value, ok := decoded.AsULCOUNTValuePDCPSNlength18()
			if !ok {
				var empty COUNTvaluePDCPSNlength18
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValuePDCP-SNlength18: no selected value")
			}
			return *value, nil
		},
		encode: func(value COUNTvaluePDCPSNlength18, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(217), rowULCOUNTValuePDCPSNlength18: &value}).encodeFresh(fresh, budget)
		}, capture: func(v COUNTvaluePDCPSNlength18, options aper.DecodeState) (COUNTvaluePDCPSNlength18, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCOUNTvaluePDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v COUNTvaluePDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCOUNTvaluePDCPSNlength18(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTvaluePDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value COUNTvaluePDCPSNlength18) BearersSubjectToStatusTransferItemExtIEsValue {
		return BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(217), rowULCOUNTValuePDCPSNlength18: &value}
	}, get: func(value *BearersSubjectToStatusTransferItemExtIEsValue) (*COUNTvaluePDCPSNlength18, bool) {
		return value.AsULCOUNTValuePDCPSNlength18()
	}}
}
func (BearersSubjectToStatusTransferItemExtIETable) infoDLCOUNTValuePDCPSNlength18() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(218), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvaluePDCP-SNlength18"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-DLCOUNTValuePDCP-SNlength18"}}}
}

// DLCOUNTValuePDCPSNlength18 returns the typed binding for the DLCOUNTValuePDCPSNlength18 row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) DLCOUNTValuePDCPSNlength18() BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding{info: t.infoDLCOUNTValuePDCPSNlength18(), codec: COUNTvaluePDCPSNlength18ValueCodec{path: "COUNTvaluePDCPSNlength18",
		decode: func(data []byte, options aper.DecodeState) (COUNTvaluePDCPSNlength18, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty COUNTvaluePDCPSNlength18
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("COUNTvaluePDCPSNlength18")
			var zero BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(218), raw)
			if err != nil {
				var empty COUNTvaluePDCPSNlength18
				return empty, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
			}
			value, ok := decoded.AsDLCOUNTValuePDCPSNlength18()
			if !ok {
				var empty COUNTvaluePDCPSNlength18
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValuePDCP-SNlength18: no selected value")
			}
			return *value, nil
		},
		encode: func(value COUNTvaluePDCPSNlength18, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(218), rowDLCOUNTValuePDCPSNlength18: &value}).encodeFresh(fresh, budget)
		}, capture: func(v COUNTvaluePDCPSNlength18, options aper.DecodeState) (COUNTvaluePDCPSNlength18, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCOUNTvaluePDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v COUNTvaluePDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCOUNTvaluePDCPSNlength18(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTvaluePDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value COUNTvaluePDCPSNlength18) BearersSubjectToStatusTransferItemExtIEsValue {
		return BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(218), rowDLCOUNTValuePDCPSNlength18: &value}
	}, get: func(value *BearersSubjectToStatusTransferItemExtIEsValue) (*COUNTvaluePDCPSNlength18, bool) {
		return value.AsDLCOUNTValuePDCPSNlength18()
	}}
}
func (BearersSubjectToStatusTransferItemExtIETable) infoReceiveStatusOfULPDCPSDUsPDCPSNlength18() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(219), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ReceiveStatusOfULPDCPSDUsPDCP-SNlength18"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18"}}}
}

// ReceiveStatusOfULPDCPSDUsPDCPSNlength18 returns the typed binding for the ReceiveStatusOfULPDCPSDUsPDCPSNlength18 row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ReceiveStatusOfULPDCPSDUsPDCPSNlength18() BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding{info: t.infoReceiveStatusOfULPDCPSDUsPDCPSNlength18(), codec: func() s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec {
		sealed := s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec{}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldPath(&sealed) = "ReceiveStatusOfULPDCPSDUsPDCPSNlength18"
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ReceiveStatusOfULPDCPSDUsPDCPSNlength18")
			var zero BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(219), raw)
			if err != nil {
				var empty s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
				return empty, runtime.WrapDecodePath(err, "ReceiveStatusOfULPDCPSDUsPDCPSNlength18")
			}
			value, ok := decoded.AsReceiveStatusOfULPDCPSDUsPDCPSNlength18()
			if !ok {
				var empty s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldEncode(&sealed) = func(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(219), rowReceiveStatusOfULPDCPSDUsPDCPSNlength18: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldCapture(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldCompare(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReceiveStatusOfULPDCPSDUsPDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18) BearersSubjectToStatusTransferItemExtIEsValue {
			return BearersSubjectToStatusTransferItemExtIEsValue{id: s00.ProtocolIEID(219), rowReceiveStatusOfULPDCPSDUsPDCPSNlength18: &value}
		}, get: func(value *BearersSubjectToStatusTransferItemExtIEsValue) (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, bool) {
			return value.AsReceiveStatusOfULPDCPSDUsPDCPSNlength18()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(179):
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ULCOUNTValueExtended requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(180):
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DLCOUNTValueExtended requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(181):
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ReceiveStatusOfULPDCPSDUsExtended requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(217):
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ULCOUNTValuePDCP-SNlength18 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(218):
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DLCOUNTValuePDCP-SNlength18 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(219):
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return BearersSubjectToStatusTransferItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: BearersSubjectToStatusTransferItemExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type DAPSResponseInfoListIETable struct{}

func DAPSResponseInfoListIEs() DAPSResponseInfoListIETable { return DAPSResponseInfoListIETable{} }

// ID returns the ASN.1 object-set identity of DAPSResponseInfoListIETable.
func (DAPSResponseInfoListIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoListIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DAPSResponseInfoListIETable.
func (DAPSResponseInfoListIETable) Table() s00.DAPSResponseInfoListIEValueIETable {
	return func() s00.DAPSResponseInfoListIEValueIETable {
		sealed := s00.DAPSResponseInfoListIEValueIETable{}
		*s00.BridgeDAPSResponseInfoListIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (DAPSResponseInfoListIETable) infoDAPSResponseInfoItem() s00.FieldInfo {
	return s00.FieldInfo{Table: DAPSResponseInfoListIEs().ID(), ID: s00.ProtocolIEID(319), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoListIEs", Row: "id-DAPSResponseInfoItem"}}}
}

// DAPSResponseInfoItem returns the typed binding for the DAPSResponseInfoItem row of DAPSResponseInfoListIETable.
func (t DAPSResponseInfoListIETable) DAPSResponseInfoItem() DAPSResponseInfoListDAPSResponseInfoItemIEBinding {
	return DAPSResponseInfoListDAPSResponseInfoItemIEBinding{info: t.infoDAPSResponseInfoItem(), codec: DAPSResponseInfoItemValueCodec{path: "DAPSResponseInfoItem",
		decode: func(data []byte, options aper.DecodeState) (DAPSResponseInfoItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty DAPSResponseInfoItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DAPSResponseInfoItem")
			var zero DAPSResponseInfoListIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(319), raw)
			if err != nil {
				var empty DAPSResponseInfoItem
				return empty, runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
			}
			value, ok := decoded.AsDAPSResponseInfoItem()
			if !ok {
				var empty DAPSResponseInfoItem
				return empty, fmt.Errorf("binding DAPSResponseInfoListIEs.id-DAPSResponseInfoItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value DAPSResponseInfoItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DAPSResponseInfoListIEValue{id: s00.ProtocolIEID(319), rowDAPSResponseInfoItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v DAPSResponseInfoItem, options aper.DecodeState) (DAPSResponseInfoItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APDAPSResponseInfoItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v DAPSResponseInfoItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APDAPSResponseInfoItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DAPSResponseInfoItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value DAPSResponseInfoItem) DAPSResponseInfoListIEValue {
		return DAPSResponseInfoListIEValue{id: s00.ProtocolIEID(319), rowDAPSResponseInfoItem: &value}
	}, get: func(value *DAPSResponseInfoListIEValue) (*DAPSResponseInfoItem, bool) {
		return value.AsDAPSResponseInfoItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DAPSResponseInfoListIETable.
func (t DAPSResponseInfoListIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (DAPSResponseInfoListIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(319):
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("known IE id-DAPSResponseInfoItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Opaque")
		}
		return DAPSResponseInfoListIEField{Id: id, Criticality: criticality, Value: DAPSResponseInfoListIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ActivatedCellsListItemCodec binds the complete source value type.
func ActivatedCellsListItemCodec() ActivatedCellsListItemValueCodec {
	return ActivatedCellsListItemValueCodec{path: "ActivatedCellsListItem", decode: func(data []byte, options aper.DecodeState) (ActivatedCellsListItem, error) {
		var value ActivatedCellsListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ActivatedCellsListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ActivatedCellsListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ActivatedCellsListItem, options aper.DecodeState) (ActivatedCellsListItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APActivatedCellsListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ActivatedCellsListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APActivatedCellsListItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ActivatedCellsListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// AllocationAndRetentionPriorityCodec binds the complete source value type.
func AllocationAndRetentionPriorityCodec() AllocationAndRetentionPriorityValueCodec {
	return AllocationAndRetentionPriorityValueCodec{path: "AllocationAndRetentionPriority", decode: func(data []byte, options aper.DecodeState) (AllocationAndRetentionPriority, error) {
		var value AllocationAndRetentionPriority
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AllocationAndRetentionPriority{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AllocationAndRetentionPriority, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AllocationAndRetentionPriority, options aper.DecodeState) (AllocationAndRetentionPriority, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAllocationAndRetentionPriority(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v AllocationAndRetentionPriority, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeCompareS1APAllocationAndRetentionPriority(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AllocationAndRetentionPriority"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CGICodec binds the complete source value type.
func CGICodec() CGIValueCodec {
	return CGIValueCodec{path: "CGI", decode: func(data []byte, options aper.DecodeState) (CGI, error) {
		var value CGI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CGI{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CGI, options aper.DecodeState) (CGI, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCGI(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v CGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCGI(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CGI"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CNTypeRestrictionsItemCodec binds the complete source value type.
func CNTypeRestrictionsItemCodec() CNTypeRestrictionsItemValueCodec {
	return CNTypeRestrictionsItemValueCodec{path: "CNTypeRestrictionsItem", decode: func(data []byte, options aper.DecodeState) (CNTypeRestrictionsItem, error) {
		var value CNTypeRestrictionsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CNTypeRestrictionsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CNTypeRestrictionsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CNTypeRestrictionsItem, options aper.DecodeState) (CNTypeRestrictionsItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCNTypeRestrictionsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CNTypeRestrictionsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCNTypeRestrictionsItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CNTypeRestrictionsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// COUNTValueExtendedCodec binds the complete APER value type.
func COUNTValueExtendedCodec() COUNTValueExtendedValueCodec {
	return BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValueExtended().Codec()
}

// COUNTvalueCodec binds the complete source value type.
func COUNTvalueCodec() COUNTvalueValueCodec {
	return COUNTvalueValueCodec{path: "COUNTvalue", decode: func(data []byte, options aper.DecodeState) (COUNTvalue, error) {
		var value COUNTvalue
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return COUNTvalue{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value COUNTvalue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v COUNTvalue, options aper.DecodeState) (COUNTvalue, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureS1APCOUNTvalue(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v COUNTvalue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCOUNTvalue(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTvalue"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// COUNTvaluePDCPSNlength18Codec binds the complete APER value type.
func COUNTvaluePDCPSNlength18Codec() COUNTvaluePDCPSNlength18ValueCodec {
	return BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValuePDCPSNlength18().Codec()
}

// CSGIdListItemCodec binds the complete source value type.
func CSGIdListItemCodec() CSGIdListItemValueCodec {
	return CSGIdListItemValueCodec{path: "CSGIdListItem", decode: func(data []byte, options aper.DecodeState) (CSGIdListItem, error) {
		var value CSGIdListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CSGIdListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CSGIdListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CSGIdListItem, options aper.DecodeState) (CSGIdListItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCSGIdListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CSGIdListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCSGIdListItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(),

			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CandidatePCICodec binds the complete source value type.
func CandidatePCICodec() CandidatePCIValueCodec {
	return CandidatePCIValueCodec{path: "CandidatePCI", decode: func(data []byte, options aper.DecodeState) (CandidatePCI, error) {
		var value CandidatePCI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CandidatePCI{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CandidatePCI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CandidatePCI, options aper.DecodeState) (CandidatePCI, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCandidatePCI(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CandidatePCI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCandidatePCI(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CandidatePCI"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellTypeCodec binds the complete source value type.
func CellTypeCodec() CellTypeValueCodec {
	return CellTypeValueCodec{path: "CellType", decode: func(data []byte, options aper.DecodeState) (CellType, error) {
		var value CellType
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellType{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellType, options aper.DecodeState) (CellType, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APCellType(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellType(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellType"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellsToActivateListItemCodec binds the complete source value type.
func CellsToActivateListItemCodec() CellsToActivateListItemValueCodec {
	return CellsToActivateListItemValueCodec{path: "CellsToActivateListItem", decode: func(data []byte, options aper.DecodeState) (CellsToActivateListItem, error) {
		var value CellsToActivateListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellsToActivateListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellsToActivateListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellsToActivateListItem, options aper.DecodeState) (CellsToActivateListItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellsToActivateListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false,
		)
		return v, root
	}, compare: func(v CellsToActivateListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellsToActivateListItem(&v, &s)
		s.End(f, root,
			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellsToActivateListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CriticalityDiagnosticsIEItemCodec binds the complete source value type.
func CriticalityDiagnosticsIEItemCodec() CriticalityDiagnosticsIEItemValueCodec {
	return CriticalityDiagnosticsIEItemValueCodec{path: "CriticalityDiagnosticsIEItem", decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnosticsIEItem, error) {
		var value CriticalityDiagnosticsIEItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CriticalityDiagnosticsIEItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CriticalityDiagnosticsIEItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CriticalityDiagnosticsIEItem, options aper.DecodeState) (CriticalityDiagnosticsIEItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCriticalityDiagnosticsIEItem(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v CriticalityDiagnosticsIEItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APCriticalityDiagnosticsIEItem(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnosticsIEItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// DAPSResponseInfoCodec binds the complete source value type.
func DAPSResponseInfoCodec() DAPSResponseInfoValueCodec {
	return DAPSResponseInfoValueCodec{path: "DAPSResponseInfo", decode: func(data []byte, options aper.DecodeState) (DAPSResponseInfo, error) {
		var value DAPSResponseInfo
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return DAPSResponseInfo{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value DAPSResponseInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v DAPSResponseInfo, options aper.DecodeState) (DAPSResponseInfo, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APDAPSResponseInfo(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v DAPSResponseInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APDAPSResponseInfo(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DAPSResponseInfo"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// DAPSResponseInfoItemCodec binds the complete APER value type.
func DAPSResponseInfoItemCodec() DAPSResponseInfoItemValueCodec {
	return DAPSResponseInfoListIEs().DAPSResponseInfoItem().Codec()
}
func BridgeActivatedCellsListAPERValueFieldContext(v *ActivatedCellsListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeActivatedCellsListAPERValueFieldReceived(v *ActivatedCellsListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeActivatedCellsListAPERValueFieldReplay(v *ActivatedCellsListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeActivatedCellsListAPERValueFieldWithoutReplay(v *ActivatedCellsListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeActivatedCellsListItemAPERValueFieldContext(v *ActivatedCellsListItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeActivatedCellsListItemAPERValueFieldReceived(v *ActivatedCellsListItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeActivatedCellsListItemAPERValueFieldReplay(v *ActivatedCellsListItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeActivatedCellsListItemAPERValueFieldWithoutReplay(v *ActivatedCellsListItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeActivatedCellsListItemFieldExtCount(v *ActivatedCellsListItem) *int64   { return &v.extCount }
func BridgeActivatedCellsListItemFieldExtData(v *ActivatedCellsListItem) *[][]byte { return &v.extData }
func BridgeActivatedCellsListItemFieldExtOrigin(v *ActivatedCellsListItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeActivatedCellsListItemFieldExtPresent(v *ActivatedCellsListItem) *[]bool {
	return &v.extPresent
}
func BridgeActivatedCellsListItemFieldExtWire(v *ActivatedCellsListItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeActivatedCellsListItemFieldPerExtPadding(v *ActivatedCellsListItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeActivatedCellsListItemFieldPerPadding(v *ActivatedCellsListItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeActivatedCellsListItemFieldReceived(v *ActivatedCellsListItem) *bool { return &v.received }
func BridgeActivatedCellsListItemFieldReceivedAbsolute(v *ActivatedCellsListItem) *bool {
	return &v.receivedAbsolute
}
func BridgeActivatedCellsListItemFieldReceivedBytes(v *ActivatedCellsListItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeActivatedCellsListItemFieldReceivedLocation(v *ActivatedCellsListItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeActivatedCellsListItemFieldReplay(v *ActivatedCellsListItem) *aper.Snapshot {
	return &v.replay
}
func BridgeActivatedCellsListItemFieldStream(v *ActivatedCellsListItem) *aper.WireSpan {
	return &v.stream
}
func BridgeActivatedCellsListItemFieldWithoutReplay(v *ActivatedCellsListItem) *bool {
	return &v.withoutReplay
}
func BridgeActivatedCellsListItemMethodMarshalAPERBudget(v *ActivatedCellsListItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeActivatedCellsListItemMethodMarshalAPERBudgetValue(v *ActivatedCellsListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeActivatedCellsListItemMethodMarshalAPERChanged(v *ActivatedCellsListItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeActivatedCellsListItemMethodMarshalAPERChangedValue(v *ActivatedCellsListItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeActivatedCellsListItemMethodMarshalAPERLegacy(v *ActivatedCellsListItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeActivatedCellsListItemMethodMarshalAPERNewValue(v *ActivatedCellsListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeActivatedCellsListItemMethodMarshalAPERPlanned(v *ActivatedCellsListItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeActivatedCellsListItemMethodMarshalAPERTo(v *ActivatedCellsListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeActivatedCellsListItemMethodUnmarshalAPERFrom(v *ActivatedCellsListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeActivatedCellsListItemMethodUnmarshalAPERLegacy(v *ActivatedCellsListItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeActivatedCellsListItemMethodUnmarshalAPERWithOptions(v *ActivatedCellsListItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeActivatedCellsListItemValueCodecFieldCapture(v *ActivatedCellsListItemValueCodec) *func(ActivatedCellsListItem, aper.DecodeState) (ActivatedCellsListItem, aper.Snapshot) {
	return &v.capture
}
func BridgeActivatedCellsListItemValueCodecFieldCompare(v *ActivatedCellsListItemValueCodec) *func(ActivatedCellsListItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeActivatedCellsListItemValueCodecFieldContext(v *ActivatedCellsListItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeActivatedCellsListItemValueCodecFieldDecode(v *ActivatedCellsListItemValueCodec) *func([]byte, aper.DecodeState) (ActivatedCellsListItem, error) {
	return &v.decode
}
func BridgeActivatedCellsListItemValueCodecFieldEncode(v *ActivatedCellsListItemValueCodec) *func(ActivatedCellsListItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeActivatedCellsListItemValueCodecFieldPath(v *ActivatedCellsListItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeActivatedCellsListItemValueCodecMethodEncodeBudgetValue(v ActivatedCellsListItemValueCodec, a0 ActivatedCellsListItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeActivatedCellsListItemValueCodecMethodEncodeChanged(v ActivatedCellsListItemValueCodec, a0 ActivatedCellsListItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeActivatedCellsListValueCodecFieldCapture(v *ActivatedCellsListValueCodec) *func(ActivatedCellsList, aper.DecodeState) (ActivatedCellsList, aper.Snapshot) {
	return &v.capture
}
func BridgeActivatedCellsListValueCodecFieldCompare(v *ActivatedCellsListValueCodec) *func(ActivatedCellsList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeActivatedCellsListValueCodecFieldContext(v *ActivatedCellsListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeActivatedCellsListValueCodecFieldDecode(v *ActivatedCellsListValueCodec) *func([]byte, aper.DecodeState) (ActivatedCellsList, error) {
	return &v.decode
}
func BridgeActivatedCellsListValueCodecFieldEncode(v *ActivatedCellsListValueCodec) *func(ActivatedCellsList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeActivatedCellsListValueCodecFieldPath(v *ActivatedCellsListValueCodec) *aper.Path {
	return &v.path
}
func BridgeActivatedCellsListValueCodecMethodEncodeBudgetValue(v ActivatedCellsListValueCodec, a0 ActivatedCellsList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeActivatedCellsListValueCodecMethodEncodeChanged(v ActivatedCellsListValueCodec, a0 ActivatedCellsList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAllocationAndRetentionPriorityAPERValueFieldContext(v *AllocationAndRetentionPriorityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAllocationAndRetentionPriorityAPERValueFieldReceived(v *AllocationAndRetentionPriorityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAllocationAndRetentionPriorityAPERValueFieldReplay(v *AllocationAndRetentionPriorityAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAllocationAndRetentionPriorityAPERValueFieldWithoutReplay(v *AllocationAndRetentionPriorityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAllocationAndRetentionPriorityFieldExtCount(v *AllocationAndRetentionPriority) *int64 {
	return &v.extCount
}
func BridgeAllocationAndRetentionPriorityFieldExtData(v *AllocationAndRetentionPriority) *[][]byte {
	return &v.extData
}
func BridgeAllocationAndRetentionPriorityFieldExtOrigin(v *AllocationAndRetentionPriority) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAllocationAndRetentionPriorityFieldExtPresent(v *AllocationAndRetentionPriority) *[]bool {
	return &v.extPresent
}
func BridgeAllocationAndRetentionPriorityFieldExtWire(v *AllocationAndRetentionPriority) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAllocationAndRetentionPriorityFieldIEExtensionsIndef(v *AllocationAndRetentionPriority) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAllocationAndRetentionPriorityFieldPerExtPadding(v *AllocationAndRetentionPriority) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAllocationAndRetentionPriorityFieldPerPadding(v *AllocationAndRetentionPriority) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAllocationAndRetentionPriorityFieldReceived(v *AllocationAndRetentionPriority) *bool {
	return &v.received
}
func BridgeAllocationAndRetentionPriorityFieldReceivedAbsolute(v *AllocationAndRetentionPriority) *bool {
	return &v.receivedAbsolute
}
func BridgeAllocationAndRetentionPriorityFieldReceivedBytes(v *AllocationAndRetentionPriority) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAllocationAndRetentionPriorityFieldReceivedLocation(v *AllocationAndRetentionPriority) *aper.Location {
	return &v.receivedLocation
}
func BridgeAllocationAndRetentionPriorityFieldReplay(v *AllocationAndRetentionPriority) *aper.Snapshot {
	return &v.replay
}
func BridgeAllocationAndRetentionPriorityFieldStream(v *AllocationAndRetentionPriority) *aper.WireSpan {
	return &v.stream
}
func BridgeAllocationAndRetentionPriorityFieldWithoutReplay(v *AllocationAndRetentionPriority) *bool {
	return &v.withoutReplay
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERBudget(v *AllocationAndRetentionPriority, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERBudgetValue(v *AllocationAndRetentionPriority, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERChanged(v *AllocationAndRetentionPriority, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERChangedValue(v *AllocationAndRetentionPriority, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERLegacy(v *AllocationAndRetentionPriority) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERNewValue(v *AllocationAndRetentionPriority, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERPlanned(v *AllocationAndRetentionPriority, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERTo(v *AllocationAndRetentionPriority, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAllocationAndRetentionPriorityMethodUnmarshalAPERFrom(v *AllocationAndRetentionPriority, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAllocationAndRetentionPriorityMethodUnmarshalAPERLegacy(v *AllocationAndRetentionPriority, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAllocationAndRetentionPriorityMethodUnmarshalAPERWithOptions(v *AllocationAndRetentionPriority, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAllocationAndRetentionPriorityValueCodecFieldCapture(v *AllocationAndRetentionPriorityValueCodec) *func(AllocationAndRetentionPriority, aper.DecodeState) (AllocationAndRetentionPriority, aper.Snapshot) {
	return &v.capture
}
func BridgeAllocationAndRetentionPriorityValueCodecFieldCompare(v *AllocationAndRetentionPriorityValueCodec) *func(AllocationAndRetentionPriority, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAllocationAndRetentionPriorityValueCodecFieldContext(v *AllocationAndRetentionPriorityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAllocationAndRetentionPriorityValueCodecFieldDecode(v *AllocationAndRetentionPriorityValueCodec) *func([]byte, aper.DecodeState) (AllocationAndRetentionPriority, error) {
	return &v.decode
}
func BridgeAllocationAndRetentionPriorityValueCodecFieldEncode(v *AllocationAndRetentionPriorityValueCodec) *func(AllocationAndRetentionPriority, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAllocationAndRetentionPriorityValueCodecFieldPath(v *AllocationAndRetentionPriorityValueCodec) *aper.Path {
	return &v.path
}
func BridgeAllocationAndRetentionPriorityValueCodecMethodEncodeBudgetValue(v AllocationAndRetentionPriorityValueCodec, a0 AllocationAndRetentionPriority, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeAllocationAndRetentionPriorityValueCodecMethodEncodeChanged(v AllocationAndRetentionPriorityValueCodec, a0 AllocationAndRetentionPriority, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldExtCount(v *BearersSubjectToEarlyStatusTransferItem) *int64 {
	return &v.extCount
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldExtData(v *BearersSubjectToEarlyStatusTransferItem) *[][]byte {
	return &v.extData
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldExtOrigin(v *BearersSubjectToEarlyStatusTransferItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldExtPresent(v *BearersSubjectToEarlyStatusTransferItem) *[]bool {
	return &v.extPresent
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldExtWire(v *BearersSubjectToEarlyStatusTransferItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldIEExtensionsIndef(v *BearersSubjectToEarlyStatusTransferItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldPerExtPadding(v *BearersSubjectToEarlyStatusTransferItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldPerPadding(v *BearersSubjectToEarlyStatusTransferItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldReceived(v *BearersSubjectToEarlyStatusTransferItem) *bool {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldReceivedAbsolute(v *BearersSubjectToEarlyStatusTransferItem) *bool {
	return &v.receivedAbsolute
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldReceivedBytes(v *BearersSubjectToEarlyStatusTransferItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldReceivedLocation(v *BearersSubjectToEarlyStatusTransferItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldReplay(v *BearersSubjectToEarlyStatusTransferItem) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldStream(v *BearersSubjectToEarlyStatusTransferItem) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToEarlyStatusTransferItemFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItem) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERBudget(v *BearersSubjectToEarlyStatusTransferItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERBudgetValue(v *BearersSubjectToEarlyStatusTransferItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERChanged(v *BearersSubjectToEarlyStatusTransferItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERChangedValue(v *BearersSubjectToEarlyStatusTransferItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERLegacy(v *BearersSubjectToEarlyStatusTransferItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERNewValue(v *BearersSubjectToEarlyStatusTransferItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERPlanned(v *BearersSubjectToEarlyStatusTransferItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERTo(v *BearersSubjectToEarlyStatusTransferItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodUnmarshalAPERFrom(v *BearersSubjectToEarlyStatusTransferItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodUnmarshalAPERLegacy(v *BearersSubjectToEarlyStatusTransferItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemMethodUnmarshalAPERWithOptions(v *BearersSubjectToEarlyStatusTransferItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemExtIETableMethodInfoDLCOUNTValueExtended(v BearersSubjectToStatusTransferItemExtIETable) s00.ExtensionInfo {
	return v.infoDLCOUNTValueExtended()
}
func BridgeBearersSubjectToStatusTransferItemExtIETableMethodInfoDLCOUNTValuePDCPSNlength18(v BearersSubjectToStatusTransferItemExtIETable) s00.ExtensionInfo {
	return v.infoDLCOUNTValuePDCPSNlength18()
}
func BridgeBearersSubjectToStatusTransferItemExtIETableMethodInfoReceiveStatusOfULPDCPSDUsExtended(v BearersSubjectToStatusTransferItemExtIETable) s00.ExtensionInfo {
	return v.infoReceiveStatusOfULPDCPSDUsExtended()
}
func BridgeBearersSubjectToStatusTransferItemExtIETableMethodInfoReceiveStatusOfULPDCPSDUsPDCPSNlength18(v BearersSubjectToStatusTransferItemExtIETable) s00.ExtensionInfo {
	return v.infoReceiveStatusOfULPDCPSDUsPDCPSNlength18()
}
func BridgeBearersSubjectToStatusTransferItemExtIETableMethodInfoULCOUNTValueExtended(v BearersSubjectToStatusTransferItemExtIETable) s00.ExtensionInfo {
	return v.infoULCOUNTValueExtended()
}
func BridgeBearersSubjectToStatusTransferItemExtIETableMethodInfoULCOUNTValuePDCPSNlength18(v BearersSubjectToStatusTransferItemExtIETable) s00.ExtensionInfo {
	return v.infoULCOUNTValuePDCPSNlength18()
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldCodec(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *COUNTValueExtendedValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldGet(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *func(*BearersSubjectToStatusTransferItemExtIEsValue) (*COUNTValueExtended, bool) {
	return &v.get
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInfo(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInject(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *func(COUNTValueExtended) BearersSubjectToStatusTransferItemExtIEsValue {
	return &v.inject
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBindingFieldCodec(v *BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) *COUNTvaluePDCPSNlength18ValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBindingFieldGet(v *BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) *func(*BearersSubjectToStatusTransferItemExtIEsValue) (*COUNTvaluePDCPSNlength18, bool) {
	return &v.get
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBindingFieldInfo(v *BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBindingFieldInject(v *BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) *func(COUNTvaluePDCPSNlength18) BearersSubjectToStatusTransferItemExtIEsValue {
	return &v.inject
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerAPERValueFieldContext(v *BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldContext(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldPath(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec, a0 BearersSubjectToStatusTransferItemExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec, a0 BearersSubjectToStatusTransferItemExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldAPERValueFieldContext(v *BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldReceived(v *BearersSubjectToStatusTransferItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldReplay(v *BearersSubjectToStatusTransferItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldStream(v *BearersSubjectToStatusTransferItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v *BearersSubjectToStatusTransferItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(v *BearersSubjectToStatusTransferItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *BearersSubjectToStatusTransferItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldContext(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldPath(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec, a0 BearersSubjectToStatusTransferItemExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec, a0 BearersSubjectToStatusTransferItemExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsIEFieldFieldReceived(v *BearersSubjectToStatusTransferItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemExtIEsIEFieldFieldReplay(v *BearersSubjectToStatusTransferItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsIEFieldFieldStream(v *BearersSubjectToStatusTransferItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToStatusTransferItemExtIEsIEFieldFieldWithoutReplay(v *BearersSubjectToStatusTransferItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsIEFieldMethodMarshalAPERTo(v *BearersSubjectToStatusTransferItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *BearersSubjectToStatusTransferItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldCodec(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldGet(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *func(*BearersSubjectToStatusTransferItemExtIEsValue) (*s00.ReceiveStatusOfULPDCPSDUsExtended, bool) {
	return &v.get
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldInfo(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldInject(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *func(s00.ReceiveStatusOfULPDCPSDUsExtended) BearersSubjectToStatusTransferItemExtIEsValue {
	return &v.inject
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBindingFieldCodec(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) *s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBindingFieldGet(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) *func(*BearersSubjectToStatusTransferItemExtIEsValue) (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, bool) {
	return &v.get
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBindingFieldInfo(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBindingFieldInject(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) *func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18) BearersSubjectToStatusTransferItemExtIEsValue {
	return &v.inject
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(v *BearersSubjectToStatusTransferItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldIsOpaque(v *BearersSubjectToStatusTransferItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldOpaque(v *BearersSubjectToStatusTransferItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldReceived(v *BearersSubjectToStatusTransferItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldReplay(v *BearersSubjectToStatusTransferItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValueExtended(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTValueExtended {
	return &v.rowDLCOUNTValueExtended
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValuePDCPSNlength18(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTvaluePDCPSNlength18 {
	return &v.rowDLCOUNTValuePDCPSNlength18
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsExtended(v *BearersSubjectToStatusTransferItemExtIEsValue) **s00.ReceiveStatusOfULPDCPSDUsExtended {
	return &v.rowReceiveStatusOfULPDCPSDUsExtended
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsPDCPSNlength18(v *BearersSubjectToStatusTransferItemExtIEsValue) **s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18 {
	return &v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValueExtended(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTValueExtended {
	return &v.rowULCOUNTValueExtended
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValuePDCPSNlength18(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTvaluePDCPSNlength18 {
	return &v.rowULCOUNTValuePDCPSNlength18
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCaptureSemantics(v BearersSubjectToStatusTransferItemExtIEsValue, a0 aper.SemanticCapture) BearersSubjectToStatusTransferItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCompareSemantics(v BearersSubjectToStatusTransferItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(v BearersSubjectToStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncode(v BearersSubjectToStatusTransferItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh(v BearersSubjectToStatusTransferItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodMatchesID(v BearersSubjectToStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodReason(v BearersSubjectToStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodRule(v BearersSubjectToStatusTransferItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeBluetoothMeasurementConfigurationAPERValueFieldContext(v *BluetoothMeasurementConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBluetoothMeasurementConfigurationAPERValueFieldReceived(v *BluetoothMeasurementConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBluetoothMeasurementConfigurationAPERValueFieldReplay(v *BluetoothMeasurementConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBluetoothMeasurementConfigurationAPERValueFieldWithoutReplay(v *BluetoothMeasurementConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBluetoothMeasurementConfigurationFieldBluetoothMeasConfigNameListIndef(v *BluetoothMeasurementConfiguration) *bool {
	return &v.bluetoothMeasConfigNameListIndef
}
func BridgeBluetoothMeasurementConfigurationFieldExtCount(v *BluetoothMeasurementConfiguration) *int64 {
	return &v.extCount
}
func BridgeBluetoothMeasurementConfigurationFieldExtData(v *BluetoothMeasurementConfiguration) *[][]byte {
	return &v.extData
}
func BridgeBluetoothMeasurementConfigurationFieldExtOrigin(v *BluetoothMeasurementConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeBluetoothMeasurementConfigurationFieldExtPresent(v *BluetoothMeasurementConfiguration) *[]bool {
	return &v.extPresent
}
func BridgeBluetoothMeasurementConfigurationFieldExtWire(v *BluetoothMeasurementConfiguration) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeBluetoothMeasurementConfigurationFieldIEExtensionsIndef(v *BluetoothMeasurementConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeBluetoothMeasurementConfigurationFieldPerExtPadding(v *BluetoothMeasurementConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeBluetoothMeasurementConfigurationFieldPerPadding(v *BluetoothMeasurementConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeBluetoothMeasurementConfigurationFieldReceived(v *BluetoothMeasurementConfiguration) *bool {
	return &v.received
}
func BridgeBluetoothMeasurementConfigurationFieldReceivedAbsolute(v *BluetoothMeasurementConfiguration) *bool {
	return &v.receivedAbsolute
}
func BridgeBluetoothMeasurementConfigurationFieldReceivedBytes(v *BluetoothMeasurementConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBluetoothMeasurementConfigurationFieldReceivedLocation(v *BluetoothMeasurementConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeBluetoothMeasurementConfigurationFieldReplay(v *BluetoothMeasurementConfiguration) *aper.Snapshot {
	return &v.replay
}
func BridgeBluetoothMeasurementConfigurationFieldStream(v *BluetoothMeasurementConfiguration) *aper.WireSpan {
	return &v.stream
}
func BridgeBluetoothMeasurementConfigurationFieldWithoutReplay(v *BluetoothMeasurementConfiguration) *bool {
	return &v.withoutReplay
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERBudget(v *BluetoothMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERBudgetValue(v *BluetoothMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERChanged(v *BluetoothMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERChangedValue(v *BluetoothMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERLegacy(v *BluetoothMeasurementConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERNewValue(v *BluetoothMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERPlanned(v *BluetoothMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERTo(v *BluetoothMeasurementConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBluetoothMeasurementConfigurationMethodUnmarshalAPERFrom(v *BluetoothMeasurementConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBluetoothMeasurementConfigurationMethodUnmarshalAPERLegacy(v *BluetoothMeasurementConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBluetoothMeasurementConfigurationMethodUnmarshalAPERWithOptions(v *BluetoothMeasurementConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldCapture(v *BluetoothMeasurementConfigurationValueCodec) *func(BluetoothMeasurementConfiguration, aper.DecodeState) (BluetoothMeasurementConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldCompare(v *BluetoothMeasurementConfigurationValueCodec) *func(BluetoothMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldContext(v *BluetoothMeasurementConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldDecode(v *BluetoothMeasurementConfigurationValueCodec) *func([]byte, aper.DecodeState) (BluetoothMeasurementConfiguration, error) {
	return &v.decode
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldEncode(v *BluetoothMeasurementConfigurationValueCodec) *func(BluetoothMeasurementConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldPath(v *BluetoothMeasurementConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeBluetoothMeasurementConfigurationValueCodecMethodEncodeBudgetValue(v BluetoothMeasurementConfigurationValueCodec, a0 BluetoothMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBluetoothMeasurementConfigurationValueCodecMethodEncodeChanged(v BluetoothMeasurementConfigurationValueCodec, a0 BluetoothMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCGIAPERValueFieldContext(v *CGIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeCGIAPERValueFieldReceived(v *CGIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeCGIAPERValueFieldReplay(v *CGIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeCGIAPERValueFieldWithoutReplay(v *CGIAPERValue) *bool             { return &v.withoutReplay }
func BridgeCGIFieldExtCount(v *CGI) *int64                                   { return &v.extCount }
func BridgeCGIFieldExtData(v *CGI) *[][]byte                                 { return &v.extData }
func BridgeCGIFieldExtOrigin(v *CGI) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeCGIFieldExtPresent(v *CGI) *[]bool                                { return &v.extPresent }
func BridgeCGIFieldExtWire(v *CGI) *[]aper.WireSpan                          { return &v.extWire }
func BridgeCGIFieldIEExtensionsIndef(v *CGI) *bool                           { return &v.iEExtensionsIndef }
func BridgeCGIFieldPerExtPadding(v *CGI) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeCGIFieldPerPadding(v *CGI) *aper.FinalPadding                     { return &v.perPadding }
func BridgeCGIFieldReceived(v *CGI) *bool                                    { return &v.received }
func BridgeCGIFieldReceivedAbsolute(v *CGI) *bool                            { return &v.receivedAbsolute }
func BridgeCGIFieldReceivedBytes(v *CGI) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeCGIFieldReceivedLocation(v *CGI) *aper.Location                   { return &v.receivedLocation }
func BridgeCGIFieldReplay(v *CGI) *aper.Snapshot                             { return &v.replay }
func BridgeCGIFieldStream(v *CGI) *aper.WireSpan                             { return &v.stream }
func BridgeCGIFieldWithoutReplay(v *CGI) *bool                               { return &v.withoutReplay }
func BridgeCGIMethodMarshalAPERBudget(v *CGI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCGIMethodMarshalAPERBudgetValue(v *CGI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCGIMethodMarshalAPERChanged(v *CGI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCGIMethodMarshalAPERChangedValue(v *CGI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCGIMethodMarshalAPERLegacy(v *CGI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeCGIMethodMarshalAPERNewValue(v *CGI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCGIMethodMarshalAPERPlanned(v *CGI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCGIMethodMarshalAPERTo(v *CGI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCGIMethodUnmarshalAPERFrom(v *CGI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCGIMethodUnmarshalAPERLegacy(v *CGI, a0 []byte) error { return v.unmarshalAPERLegacy(a0) }
func BridgeCGIMethodUnmarshalAPERWithOptions(v *CGI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCGIValueCodecFieldCapture(v *CGIValueCodec) *func(CGI, aper.DecodeState) (CGI, aper.Snapshot) {
	return &v.capture
}
func BridgeCGIValueCodecFieldCompare(v *CGIValueCodec) *func(CGI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCGIValueCodecFieldContext(v *CGIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeCGIValueCodecFieldDecode(v *CGIValueCodec) *func([]byte, aper.DecodeState) (CGI, error) {
	return &v.decode
}
func BridgeCGIValueCodecFieldEncode(v *CGIValueCodec) *func(CGI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCGIValueCodecFieldPath(v *CGIValueCodec) *aper.Path { return &v.path }
func BridgeCGIValueCodecMethodEncodeBudgetValue(v CGIValueCodec, a0 CGI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCGIValueCodecMethodEncodeChanged(v CGIValueCodec, a0 CGI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCNTypeRestrictionsAPERValueFieldContext(v *CNTypeRestrictionsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCNTypeRestrictionsAPERValueFieldReceived(v *CNTypeRestrictionsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCNTypeRestrictionsAPERValueFieldReplay(v *CNTypeRestrictionsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCNTypeRestrictionsAPERValueFieldWithoutReplay(v *CNTypeRestrictionsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCNTypeRestrictionsItemAPERValueFieldContext(v *CNTypeRestrictionsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCNTypeRestrictionsItemAPERValueFieldReceived(v *CNTypeRestrictionsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCNTypeRestrictionsItemAPERValueFieldReplay(v *CNTypeRestrictionsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCNTypeRestrictionsItemAPERValueFieldWithoutReplay(v *CNTypeRestrictionsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCNTypeRestrictionsItemFieldExtCount(v *CNTypeRestrictionsItem) *int64   { return &v.extCount }
func BridgeCNTypeRestrictionsItemFieldExtData(v *CNTypeRestrictionsItem) *[][]byte { return &v.extData }
func BridgeCNTypeRestrictionsItemFieldExtOrigin(v *CNTypeRestrictionsItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCNTypeRestrictionsItemFieldExtPresent(v *CNTypeRestrictionsItem) *[]bool {
	return &v.extPresent
}
func BridgeCNTypeRestrictionsItemFieldExtWire(v *CNTypeRestrictionsItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCNTypeRestrictionsItemFieldIEExtensionsIndef(v *CNTypeRestrictionsItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCNTypeRestrictionsItemFieldPerExtPadding(v *CNTypeRestrictionsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCNTypeRestrictionsItemFieldPerPadding(v *CNTypeRestrictionsItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCNTypeRestrictionsItemFieldReceived(v *CNTypeRestrictionsItem) *bool { return &v.received }
func BridgeCNTypeRestrictionsItemFieldReceivedAbsolute(v *CNTypeRestrictionsItem) *bool {
	return &v.receivedAbsolute
}
func BridgeCNTypeRestrictionsItemFieldReceivedBytes(v *CNTypeRestrictionsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCNTypeRestrictionsItemFieldReceivedLocation(v *CNTypeRestrictionsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeCNTypeRestrictionsItemFieldReplay(v *CNTypeRestrictionsItem) *aper.Snapshot {
	return &v.replay
}
func BridgeCNTypeRestrictionsItemFieldStream(v *CNTypeRestrictionsItem) *aper.WireSpan {
	return &v.stream
}
func BridgeCNTypeRestrictionsItemFieldWithoutReplay(v *CNTypeRestrictionsItem) *bool {
	return &v.withoutReplay
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERBudget(v *CNTypeRestrictionsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERBudgetValue(v *CNTypeRestrictionsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERChanged(v *CNTypeRestrictionsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERChangedValue(v *CNTypeRestrictionsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERLegacy(v *CNTypeRestrictionsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERNewValue(v *CNTypeRestrictionsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERPlanned(v *CNTypeRestrictionsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERTo(v *CNTypeRestrictionsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCNTypeRestrictionsItemMethodUnmarshalAPERFrom(v *CNTypeRestrictionsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCNTypeRestrictionsItemMethodUnmarshalAPERLegacy(v *CNTypeRestrictionsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCNTypeRestrictionsItemMethodUnmarshalAPERWithOptions(v *CNTypeRestrictionsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCNTypeRestrictionsItemValueCodecFieldCapture(v *CNTypeRestrictionsItemValueCodec) *func(CNTypeRestrictionsItem, aper.DecodeState) (CNTypeRestrictionsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeCNTypeRestrictionsItemValueCodecFieldCompare(v *CNTypeRestrictionsItemValueCodec) *func(CNTypeRestrictionsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCNTypeRestrictionsItemValueCodecFieldContext(v *CNTypeRestrictionsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCNTypeRestrictionsItemValueCodecFieldDecode(v *CNTypeRestrictionsItemValueCodec) *func([]byte, aper.DecodeState) (CNTypeRestrictionsItem, error) {
	return &v.decode
}
func BridgeCNTypeRestrictionsItemValueCodecFieldEncode(v *CNTypeRestrictionsItemValueCodec) *func(CNTypeRestrictionsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCNTypeRestrictionsItemValueCodecFieldPath(v *CNTypeRestrictionsItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeCNTypeRestrictionsItemValueCodecMethodEncodeBudgetValue(v CNTypeRestrictionsItemValueCodec, a0 CNTypeRestrictionsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCNTypeRestrictionsItemValueCodecMethodEncodeChanged(v CNTypeRestrictionsItemValueCodec, a0 CNTypeRestrictionsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCNTypeRestrictionsValueCodecFieldCapture(v *CNTypeRestrictionsValueCodec) *func(CNTypeRestrictions, aper.DecodeState) (CNTypeRestrictions, aper.Snapshot) {
	return &v.capture
}
func BridgeCNTypeRestrictionsValueCodecFieldCompare(v *CNTypeRestrictionsValueCodec) *func(CNTypeRestrictions, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCNTypeRestrictionsValueCodecFieldContext(v *CNTypeRestrictionsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCNTypeRestrictionsValueCodecFieldDecode(v *CNTypeRestrictionsValueCodec) *func([]byte, aper.DecodeState) (CNTypeRestrictions, error) {
	return &v.decode
}
func BridgeCNTypeRestrictionsValueCodecFieldEncode(v *CNTypeRestrictionsValueCodec) *func(CNTypeRestrictions, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCNTypeRestrictionsValueCodecFieldPath(v *CNTypeRestrictionsValueCodec) *aper.Path {
	return &v.path
}
func BridgeCNTypeRestrictionsValueCodecMethodEncodeBudgetValue(v CNTypeRestrictionsValueCodec, a0 CNTypeRestrictions, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCNTypeRestrictionsValueCodecMethodEncodeChanged(v CNTypeRestrictionsValueCodec, a0 CNTypeRestrictions, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCOUNTValueExtendedAPERValueFieldContext(v *COUNTValueExtendedAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTValueExtendedAPERValueFieldReceived(v *COUNTValueExtendedAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCOUNTValueExtendedAPERValueFieldReplay(v *COUNTValueExtendedAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTValueExtendedAPERValueFieldWithoutReplay(v *COUNTValueExtendedAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTValueExtendedFieldExtCount(v *COUNTValueExtended) *int64   { return &v.extCount }
func BridgeCOUNTValueExtendedFieldExtData(v *COUNTValueExtended) *[][]byte { return &v.extData }
func BridgeCOUNTValueExtendedFieldExtOrigin(v *COUNTValueExtended) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCOUNTValueExtendedFieldExtPresent(v *COUNTValueExtended) *[]bool       { return &v.extPresent }
func BridgeCOUNTValueExtendedFieldExtWire(v *COUNTValueExtended) *[]aper.WireSpan { return &v.extWire }
func BridgeCOUNTValueExtendedFieldIEExtensionsIndef(v *COUNTValueExtended) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCOUNTValueExtendedFieldPerExtPadding(v *COUNTValueExtended) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCOUNTValueExtendedFieldPerPadding(v *COUNTValueExtended) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCOUNTValueExtendedFieldReceived(v *COUNTValueExtended) *bool { return &v.received }
func BridgeCOUNTValueExtendedFieldReceivedAbsolute(v *COUNTValueExtended) *bool {
	return &v.receivedAbsolute
}
func BridgeCOUNTValueExtendedFieldReceivedBytes(v *COUNTValueExtended) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCOUNTValueExtendedFieldReceivedLocation(v *COUNTValueExtended) *aper.Location {
	return &v.receivedLocation
}
func BridgeCOUNTValueExtendedFieldReplay(v *COUNTValueExtended) *aper.Snapshot { return &v.replay }
func BridgeCOUNTValueExtendedFieldStream(v *COUNTValueExtended) *aper.WireSpan { return &v.stream }
func BridgeCOUNTValueExtendedFieldWithoutReplay(v *COUNTValueExtended) *bool   { return &v.withoutReplay }
func BridgeCOUNTValueExtendedMethodMarshalAPERBudget(v *COUNTValueExtended, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCOUNTValueExtendedMethodMarshalAPERBudgetValue(v *COUNTValueExtended, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCOUNTValueExtendedMethodMarshalAPERChanged(v *COUNTValueExtended, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCOUNTValueExtendedMethodMarshalAPERChangedValue(v *COUNTValueExtended, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCOUNTValueExtendedMethodMarshalAPERLegacy(v *COUNTValueExtended) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCOUNTValueExtendedMethodMarshalAPERNewValue(v *COUNTValueExtended, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCOUNTValueExtendedMethodMarshalAPERPlanned(v *COUNTValueExtended, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCOUNTValueExtendedMethodMarshalAPERTo(v *COUNTValueExtended, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTValueExtendedMethodUnmarshalAPERFrom(v *COUNTValueExtended, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTValueExtendedMethodUnmarshalAPERLegacy(v *COUNTValueExtended, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCOUNTValueExtendedMethodUnmarshalAPERWithOptions(v *COUNTValueExtended, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCOUNTValueExtendedValueCodecFieldCapture(v *COUNTValueExtendedValueCodec) *func(COUNTValueExtended, aper.DecodeState) (COUNTValueExtended, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTValueExtendedValueCodecFieldCompare(v *COUNTValueExtendedValueCodec) *func(COUNTValueExtended, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTValueExtendedValueCodecFieldContext(v *COUNTValueExtendedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTValueExtendedValueCodecFieldDecode(v *COUNTValueExtendedValueCodec) *func([]byte, aper.DecodeState) (COUNTValueExtended, error) {
	return &v.decode
}
func BridgeCOUNTValueExtendedValueCodecFieldEncode(v *COUNTValueExtendedValueCodec) *func(COUNTValueExtended, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTValueExtendedValueCodecFieldPath(v *COUNTValueExtendedValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTValueExtendedValueCodecMethodEncodeBudgetValue(v COUNTValueExtendedValueCodec, a0 COUNTValueExtended, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCOUNTValueExtendedValueCodecMethodEncodeChanged(v COUNTValueExtendedValueCodec, a0 COUNTValueExtended, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCOUNTvalueAPERValueFieldContext(v *COUNTvalueAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvalueAPERValueFieldReceived(v *COUNTvalueAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCOUNTvalueAPERValueFieldReplay(v *COUNTvalueAPERValue) *aper.Snapshot { return &v.replay }
func BridgeCOUNTvalueAPERValueFieldWithoutReplay(v *COUNTvalueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTvalueFieldExtCount(v *COUNTvalue) *int64                { return &v.extCount }
func BridgeCOUNTvalueFieldExtData(v *COUNTvalue) *[][]byte              { return &v.extData }
func BridgeCOUNTvalueFieldExtOrigin(v *COUNTvalue) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeCOUNTvalueFieldExtPresent(v *COUNTvalue) *[]bool             { return &v.extPresent }
func BridgeCOUNTvalueFieldExtWire(v *COUNTvalue) *[]aper.WireSpan       { return &v.extWire }
func BridgeCOUNTvalueFieldIEExtensionsIndef(v *COUNTvalue) *bool        { return &v.iEExtensionsIndef }
func BridgeCOUNTvalueFieldPerExtPadding(v *COUNTvalue) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCOUNTvalueFieldPerPadding(v *COUNTvalue) *aper.FinalPadding   { return &v.perPadding }
func BridgeCOUNTvalueFieldReceived(v *COUNTvalue) *bool                  { return &v.received }
func BridgeCOUNTvalueFieldReceivedAbsolute(v *COUNTvalue) *bool          { return &v.receivedAbsolute }
func BridgeCOUNTvalueFieldReceivedBytes(v *COUNTvalue) *aper.WireSpan    { return &v.receivedBytes }
func BridgeCOUNTvalueFieldReceivedLocation(v *COUNTvalue) *aper.Location { return &v.receivedLocation }
func BridgeCOUNTvalueFieldReplay(v *COUNTvalue) *aper.Snapshot           { return &v.replay }
func BridgeCOUNTvalueFieldStream(v *COUNTvalue) *aper.WireSpan           { return &v.stream }
func BridgeCOUNTvalueFieldWithoutReplay(v *COUNTvalue) *bool             { return &v.withoutReplay }
func BridgeCOUNTvalueMethodMarshalAPERBudget(v *COUNTvalue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCOUNTvalueMethodMarshalAPERBudgetValue(v *COUNTvalue, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCOUNTvalueMethodMarshalAPERChanged(v *COUNTvalue, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCOUNTvalueMethodMarshalAPERChangedValue(v *COUNTvalue, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCOUNTvalueMethodMarshalAPERLegacy(v *COUNTvalue) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCOUNTvalueMethodMarshalAPERNewValue(v *COUNTvalue, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCOUNTvalueMethodMarshalAPERPlanned(v *COUNTvalue, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCOUNTvalueMethodMarshalAPERTo(v *COUNTvalue, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTvalueMethodUnmarshalAPERFrom(v *COUNTvalue, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTvalueMethodUnmarshalAPERLegacy(v *COUNTvalue, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCOUNTvalueMethodUnmarshalAPERWithOptions(v *COUNTvalue, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18APERValueFieldContext(v *COUNTvaluePDCPSNlength18APERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvaluePDCPSNlength18APERValueFieldReceived(v *COUNTvaluePDCPSNlength18APERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCOUNTvaluePDCPSNlength18APERValueFieldReplay(v *COUNTvaluePDCPSNlength18APERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTvaluePDCPSNlength18APERValueFieldWithoutReplay(v *COUNTvaluePDCPSNlength18APERValue) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTvaluePDCPSNlength18FieldExtCount(v *COUNTvaluePDCPSNlength18) *int64 {
	return &v.extCount
}
func BridgeCOUNTvaluePDCPSNlength18FieldExtData(v *COUNTvaluePDCPSNlength18) *[][]byte {
	return &v.extData
}
func BridgeCOUNTvaluePDCPSNlength18FieldExtOrigin(v *COUNTvaluePDCPSNlength18) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCOUNTvaluePDCPSNlength18FieldExtPresent(v *COUNTvaluePDCPSNlength18) *[]bool {
	return &v.extPresent
}
func BridgeCOUNTvaluePDCPSNlength18FieldExtWire(v *COUNTvaluePDCPSNlength18) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCOUNTvaluePDCPSNlength18FieldIEExtensionsIndef(v *COUNTvaluePDCPSNlength18) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCOUNTvaluePDCPSNlength18FieldPerExtPadding(v *COUNTvaluePDCPSNlength18) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCOUNTvaluePDCPSNlength18FieldPerPadding(v *COUNTvaluePDCPSNlength18) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCOUNTvaluePDCPSNlength18FieldReceived(v *COUNTvaluePDCPSNlength18) *bool {
	return &v.received
}
func BridgeCOUNTvaluePDCPSNlength18FieldReceivedAbsolute(v *COUNTvaluePDCPSNlength18) *bool {
	return &v.receivedAbsolute
}
func BridgeCOUNTvaluePDCPSNlength18FieldReceivedBytes(v *COUNTvaluePDCPSNlength18) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCOUNTvaluePDCPSNlength18FieldReceivedLocation(v *COUNTvaluePDCPSNlength18) *aper.Location {
	return &v.receivedLocation
}
func BridgeCOUNTvaluePDCPSNlength18FieldReplay(v *COUNTvaluePDCPSNlength18) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTvaluePDCPSNlength18FieldStream(v *COUNTvaluePDCPSNlength18) *aper.WireSpan {
	return &v.stream
}
func BridgeCOUNTvaluePDCPSNlength18FieldWithoutReplay(v *COUNTvaluePDCPSNlength18) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERBudget(v *COUNTvaluePDCPSNlength18, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERBudgetValue(v *COUNTvaluePDCPSNlength18, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERChanged(v *COUNTvaluePDCPSNlength18, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERChangedValue(v *COUNTvaluePDCPSNlength18, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERLegacy(v *COUNTvaluePDCPSNlength18) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERNewValue(v *COUNTvaluePDCPSNlength18, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERPlanned(v *COUNTvaluePDCPSNlength18, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERTo(v *COUNTvaluePDCPSNlength18, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTvaluePDCPSNlength18MethodUnmarshalAPERFrom(v *COUNTvaluePDCPSNlength18, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTvaluePDCPSNlength18MethodUnmarshalAPERLegacy(v *COUNTvaluePDCPSNlength18, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCOUNTvaluePDCPSNlength18MethodUnmarshalAPERWithOptions(v *COUNTvaluePDCPSNlength18, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecFieldCapture(v *COUNTvaluePDCPSNlength18ValueCodec) *func(COUNTvaluePDCPSNlength18, aper.DecodeState) (COUNTvaluePDCPSNlength18, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecFieldCompare(v *COUNTvaluePDCPSNlength18ValueCodec) *func(COUNTvaluePDCPSNlength18, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecFieldContext(v *COUNTvaluePDCPSNlength18ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecFieldDecode(v *COUNTvaluePDCPSNlength18ValueCodec) *func([]byte, aper.DecodeState) (COUNTvaluePDCPSNlength18, error) {
	return &v.decode
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecFieldEncode(v *COUNTvaluePDCPSNlength18ValueCodec) *func(COUNTvaluePDCPSNlength18, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecFieldPath(v *COUNTvaluePDCPSNlength18ValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecMethodEncodeBudgetValue(v COUNTvaluePDCPSNlength18ValueCodec, a0 COUNTvaluePDCPSNlength18, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCOUNTvaluePDCPSNlength18ValueCodecMethodEncodeChanged(v COUNTvaluePDCPSNlength18ValueCodec, a0 COUNTvaluePDCPSNlength18, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCOUNTvalueValueCodecFieldCapture(v *COUNTvalueValueCodec) *func(COUNTvalue, aper.DecodeState) (COUNTvalue, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTvalueValueCodecFieldCompare(v *COUNTvalueValueCodec) *func(COUNTvalue, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTvalueValueCodecFieldContext(v *COUNTvalueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvalueValueCodecFieldDecode(v *COUNTvalueValueCodec) *func([]byte, aper.DecodeState) (COUNTvalue, error) {
	return &v.decode
}
func BridgeCOUNTvalueValueCodecFieldEncode(v *COUNTvalueValueCodec) *func(COUNTvalue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTvalueValueCodecFieldPath(v *COUNTvalueValueCodec) *aper.Path { return &v.path }
func BridgeCOUNTvalueValueCodecMethodEncodeBudgetValue(v COUNTvalueValueCodec, a0 COUNTvalue, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCOUNTvalueValueCodecMethodEncodeChanged(v COUNTvalueValueCodec, a0 COUNTvalue, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCSGIdListAPERValueFieldContext(v *CSGIdListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGIdListAPERValueFieldReceived(v *CSGIdListAPERValue) *aper.WireSpan { return &v.received }
func BridgeCSGIdListAPERValueFieldReplay(v *CSGIdListAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeCSGIdListAPERValueFieldWithoutReplay(v *CSGIdListAPERValue) *bool     { return &v.withoutReplay }
func BridgeCSGIdListItemAPERValueFieldContext(v *CSGIdListItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGIdListItemAPERValueFieldReceived(v *CSGIdListItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCSGIdListItemAPERValueFieldReplay(v *CSGIdListItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCSGIdListItemAPERValueFieldWithoutReplay(v *CSGIdListItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCSGIdListItemFieldExtCount(v *CSGIdListItem) *int64                { return &v.extCount }
func BridgeCSGIdListItemFieldExtData(v *CSGIdListItem) *[][]byte              { return &v.extData }
func BridgeCSGIdListItemFieldExtOrigin(v *CSGIdListItem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeCSGIdListItemFieldExtPresent(v *CSGIdListItem) *[]bool             { return &v.extPresent }
func BridgeCSGIdListItemFieldExtWire(v *CSGIdListItem) *[]aper.WireSpan       { return &v.extWire }
func BridgeCSGIdListItemFieldIEExtensionsIndef(v *CSGIdListItem) *bool        { return &v.iEExtensionsIndef }
func BridgeCSGIdListItemFieldPerExtPadding(v *CSGIdListItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCSGIdListItemFieldPerPadding(v *CSGIdListItem) *aper.FinalPadding { return &v.perPadding }
func BridgeCSGIdListItemFieldReceived(v *CSGIdListItem) *bool                { return &v.received }
func BridgeCSGIdListItemFieldReceivedAbsolute(v *CSGIdListItem) *bool        { return &v.receivedAbsolute }
func BridgeCSGIdListItemFieldReceivedBytes(v *CSGIdListItem) *aper.WireSpan  { return &v.receivedBytes }
func BridgeCSGIdListItemFieldReceivedLocation(v *CSGIdListItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeCSGIdListItemFieldReplay(v *CSGIdListItem) *aper.Snapshot { return &v.replay }
func BridgeCSGIdListItemFieldStream(v *CSGIdListItem) *aper.WireSpan { return &v.stream }
func BridgeCSGIdListItemFieldWithoutReplay(v *CSGIdListItem) *bool   { return &v.withoutReplay }
func BridgeCSGIdListItemMethodMarshalAPERBudget(v *CSGIdListItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCSGIdListItemMethodMarshalAPERBudgetValue(v *CSGIdListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCSGIdListItemMethodMarshalAPERChanged(v *CSGIdListItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCSGIdListItemMethodMarshalAPERChangedValue(v *CSGIdListItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCSGIdListItemMethodMarshalAPERLegacy(v *CSGIdListItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCSGIdListItemMethodMarshalAPERNewValue(v *CSGIdListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCSGIdListItemMethodMarshalAPERPlanned(v *CSGIdListItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCSGIdListItemMethodMarshalAPERTo(v *CSGIdListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCSGIdListItemMethodUnmarshalAPERFrom(v *CSGIdListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCSGIdListItemMethodUnmarshalAPERLegacy(v *CSGIdListItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCSGIdListItemMethodUnmarshalAPERWithOptions(v *CSGIdListItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCSGIdListItemValueCodecFieldCapture(v *CSGIdListItemValueCodec) *func(CSGIdListItem, aper.DecodeState) (CSGIdListItem, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGIdListItemValueCodecFieldCompare(v *CSGIdListItemValueCodec) *func(CSGIdListItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGIdListItemValueCodecFieldContext(v *CSGIdListItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGIdListItemValueCodecFieldDecode(v *CSGIdListItemValueCodec) *func([]byte, aper.DecodeState) (CSGIdListItem, error) {
	return &v.decode
}
func BridgeCSGIdListItemValueCodecFieldEncode(v *CSGIdListItemValueCodec) *func(CSGIdListItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGIdListItemValueCodecFieldPath(v *CSGIdListItemValueCodec) *aper.Path { return &v.path }
func BridgeCSGIdListItemValueCodecMethodEncodeBudgetValue(v CSGIdListItemValueCodec, a0 CSGIdListItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCSGIdListItemValueCodecMethodEncodeChanged(v CSGIdListItemValueCodec, a0 CSGIdListItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCSGIdListValueCodecFieldCapture(v *CSGIdListValueCodec) *func(CSGIdList, aper.DecodeState) (CSGIdList, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGIdListValueCodecFieldCompare(v *CSGIdListValueCodec) *func(CSGIdList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGIdListValueCodecFieldContext(v *CSGIdListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGIdListValueCodecFieldDecode(v *CSGIdListValueCodec) *func([]byte, aper.DecodeState) (CSGIdList, error) {
	return &v.decode
}
func BridgeCSGIdListValueCodecFieldEncode(v *CSGIdListValueCodec) *func(CSGIdList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGIdListValueCodecFieldPath(v *CSGIdListValueCodec) *aper.Path { return &v.path }
func BridgeCSGIdListValueCodecMethodEncodeBudgetValue(v CSGIdListValueCodec, a0 CSGIdList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCSGIdListValueCodecMethodEncodeChanged(v CSGIdListValueCodec, a0 CSGIdList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCSGMembershipInfoAPERValueFieldContext(v *CSGMembershipInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGMembershipInfoAPERValueFieldReceived(v *CSGMembershipInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCSGMembershipInfoAPERValueFieldReplay(v *CSGMembershipInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCSGMembershipInfoAPERValueFieldWithoutReplay(v *CSGMembershipInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCSGMembershipInfoFieldExtCount(v *CSGMembershipInfo) *int64   { return &v.extCount }
func BridgeCSGMembershipInfoFieldExtData(v *CSGMembershipInfo) *[][]byte { return &v.extData }
func BridgeCSGMembershipInfoFieldExtOrigin(v *CSGMembershipInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCSGMembershipInfoFieldExtPresent(v *CSGMembershipInfo) *[]bool       { return &v.extPresent }
func BridgeCSGMembershipInfoFieldExtWire(v *CSGMembershipInfo) *[]aper.WireSpan { return &v.extWire }
func BridgeCSGMembershipInfoFieldIEExtensionsIndef(v *CSGMembershipInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCSGMembershipInfoFieldPerExtPadding(v *CSGMembershipInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCSGMembershipInfoFieldPerPadding(v *CSGMembershipInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCSGMembershipInfoFieldReceived(v *CSGMembershipInfo) *bool { return &v.received }
func BridgeCSGMembershipInfoFieldReceivedAbsolute(v *CSGMembershipInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeCSGMembershipInfoFieldReceivedBytes(v *CSGMembershipInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCSGMembershipInfoFieldReceivedLocation(v *CSGMembershipInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeCSGMembershipInfoFieldReplay(v *CSGMembershipInfo) *aper.Snapshot { return &v.replay }
func BridgeCSGMembershipInfoFieldStream(v *CSGMembershipInfo) *aper.WireSpan { return &v.stream }
func BridgeCSGMembershipInfoFieldWithoutReplay(v *CSGMembershipInfo) *bool   { return &v.withoutReplay }
func BridgeCSGMembershipInfoMethodMarshalAPERBudget(v *CSGMembershipInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCSGMembershipInfoMethodMarshalAPERBudgetValue(v *CSGMembershipInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCSGMembershipInfoMethodMarshalAPERChanged(v *CSGMembershipInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCSGMembershipInfoMethodMarshalAPERChangedValue(v *CSGMembershipInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCSGMembershipInfoMethodMarshalAPERLegacy(v *CSGMembershipInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCSGMembershipInfoMethodMarshalAPERNewValue(v *CSGMembershipInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCSGMembershipInfoMethodMarshalAPERPlanned(v *CSGMembershipInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCSGMembershipInfoMethodMarshalAPERTo(v *CSGMembershipInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCSGMembershipInfoMethodUnmarshalAPERFrom(v *CSGMembershipInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCSGMembershipInfoMethodUnmarshalAPERLegacy(v *CSGMembershipInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCSGMembershipInfoMethodUnmarshalAPERWithOptions(v *CSGMembershipInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCSGMembershipInfoValueCodecFieldCapture(v *CSGMembershipInfoValueCodec) *func(CSGMembershipInfo, aper.DecodeState) (CSGMembershipInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGMembershipInfoValueCodecFieldCompare(v *CSGMembershipInfoValueCodec) *func(CSGMembershipInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGMembershipInfoValueCodecFieldContext(v *CSGMembershipInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGMembershipInfoValueCodecFieldDecode(v *CSGMembershipInfoValueCodec) *func([]byte, aper.DecodeState) (CSGMembershipInfo, error) {
	return &v.decode
}
func BridgeCSGMembershipInfoValueCodecFieldEncode(v *CSGMembershipInfoValueCodec) *func(CSGMembershipInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGMembershipInfoValueCodecFieldPath(v *CSGMembershipInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeCSGMembershipInfoValueCodecMethodEncodeBudgetValue(v CSGMembershipInfoValueCodec, a0 CSGMembershipInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCSGMembershipInfoValueCodecMethodEncodeChanged(v CSGMembershipInfoValueCodec, a0 CSGMembershipInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCandidatePCIAPERValueFieldContext(v *CandidatePCIAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCandidatePCIAPERValueFieldReceived(v *CandidatePCIAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCandidatePCIAPERValueFieldReplay(v *CandidatePCIAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCandidatePCIAPERValueFieldWithoutReplay(v *CandidatePCIAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCandidatePCIFieldExtCount(v *CandidatePCI) *int64                { return &v.extCount }
func BridgeCandidatePCIFieldExtData(v *CandidatePCI) *[][]byte              { return &v.extData }
func BridgeCandidatePCIFieldExtOrigin(v *CandidatePCI) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeCandidatePCIFieldExtPresent(v *CandidatePCI) *[]bool             { return &v.extPresent }
func BridgeCandidatePCIFieldExtWire(v *CandidatePCI) *[]aper.WireSpan       { return &v.extWire }
func BridgeCandidatePCIFieldPerExtPadding(v *CandidatePCI) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCandidatePCIFieldPerPadding(v *CandidatePCI) *aper.FinalPadding { return &v.perPadding }
func BridgeCandidatePCIFieldReceived(v *CandidatePCI) *bool                { return &v.received }
func BridgeCandidatePCIFieldReceivedAbsolute(v *CandidatePCI) *bool        { return &v.receivedAbsolute }
func BridgeCandidatePCIFieldReceivedBytes(v *CandidatePCI) *aper.WireSpan  { return &v.receivedBytes }
func BridgeCandidatePCIFieldReceivedLocation(v *CandidatePCI) *aper.Location {
	return &v.receivedLocation
}
func BridgeCandidatePCIFieldReplay(v *CandidatePCI) *aper.Snapshot { return &v.replay }
func BridgeCandidatePCIFieldStream(v *CandidatePCI) *aper.WireSpan { return &v.stream }
func BridgeCandidatePCIFieldWithoutReplay(v *CandidatePCI) *bool   { return &v.withoutReplay }
func BridgeCandidatePCIListAPERValueFieldContext(v *CandidatePCIListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCandidatePCIListAPERValueFieldReceived(v *CandidatePCIListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCandidatePCIListAPERValueFieldReplay(v *CandidatePCIListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCandidatePCIListAPERValueFieldWithoutReplay(v *CandidatePCIListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCandidatePCIListValueCodecFieldCapture(v *CandidatePCIListValueCodec) *func(CandidatePCIList, aper.DecodeState) (CandidatePCIList, aper.Snapshot) {
	return &v.capture
}
func BridgeCandidatePCIListValueCodecFieldCompare(v *CandidatePCIListValueCodec) *func(CandidatePCIList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCandidatePCIListValueCodecFieldContext(v *CandidatePCIListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCandidatePCIListValueCodecFieldDecode(v *CandidatePCIListValueCodec) *func([]byte, aper.DecodeState) (CandidatePCIList, error) {
	return &v.decode
}
func BridgeCandidatePCIListValueCodecFieldEncode(v *CandidatePCIListValueCodec) *func(CandidatePCIList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCandidatePCIListValueCodecFieldPath(v *CandidatePCIListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCandidatePCIListValueCodecMethodEncodeBudgetValue(v CandidatePCIListValueCodec, a0 CandidatePCIList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCandidatePCIListValueCodecMethodEncodeChanged(v CandidatePCIListValueCodec, a0 CandidatePCIList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCandidatePCIMethodMarshalAPERBudget(v *CandidatePCI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCandidatePCIMethodMarshalAPERBudgetValue(v *CandidatePCI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCandidatePCIMethodMarshalAPERChanged(v *CandidatePCI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCandidatePCIMethodMarshalAPERChangedValue(v *CandidatePCI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCandidatePCIMethodMarshalAPERLegacy(v *CandidatePCI) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCandidatePCIMethodMarshalAPERNewValue(v *CandidatePCI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCandidatePCIMethodMarshalAPERPlanned(v *CandidatePCI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCandidatePCIMethodMarshalAPERTo(v *CandidatePCI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCandidatePCIMethodUnmarshalAPERFrom(v *CandidatePCI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCandidatePCIMethodUnmarshalAPERLegacy(v *CandidatePCI, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCandidatePCIMethodUnmarshalAPERWithOptions(v *CandidatePCI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCandidatePCIValueCodecFieldCapture(v *CandidatePCIValueCodec) *func(CandidatePCI, aper.DecodeState) (CandidatePCI, aper.Snapshot) {
	return &v.capture
}
func BridgeCandidatePCIValueCodecFieldCompare(v *CandidatePCIValueCodec) *func(CandidatePCI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCandidatePCIValueCodecFieldContext(v *CandidatePCIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCandidatePCIValueCodecFieldDecode(v *CandidatePCIValueCodec) *func([]byte, aper.DecodeState) (CandidatePCI, error) {
	return &v.decode
}
func BridgeCandidatePCIValueCodecFieldEncode(v *CandidatePCIValueCodec) *func(CandidatePCI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCandidatePCIValueCodecFieldPath(v *CandidatePCIValueCodec) *aper.Path { return &v.path }
func BridgeCandidatePCIValueCodecMethodEncodeBudgetValue(v CandidatePCIValueCodec, a0 CandidatePCI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCandidatePCIValueCodecMethodEncodeChanged(v CandidatePCIValueCodec, a0 CandidatePCI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCauseAPERValueFieldContext(v *CauseAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeCauseAPERValueFieldReceived(v *CauseAPERValue) *aper.WireSpan         { return &v.received }
func BridgeCauseAPERValueFieldReplay(v *CauseAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeCauseAPERValueFieldWithoutReplay(v *CauseAPERValue) *bool             { return &v.withoutReplay }
func BridgeCauseFieldPerOpenTypePadding(v *Cause) *aper.CompletePadding          { return &v.perOpenTypePadding }
func BridgeCauseFieldPerPadding(v *Cause) *aper.CompletePadding                  { return &v.perPadding }
func BridgeCauseFieldReceived(v *Cause) *bool                                    { return &v.received }
func BridgeCauseFieldReceivedAbsolute(v *Cause) *bool                            { return &v.receivedAbsolute }
func BridgeCauseFieldReceivedBytes(v *Cause) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeCauseFieldReceivedLocation(v *Cause) *aper.Location                   { return &v.receivedLocation }
func BridgeCauseFieldReplay(v *Cause) *aper.Snapshot                             { return &v.replay }
func BridgeCauseFieldStream(v *Cause) *aper.WireSpan                             { return &v.stream }
func BridgeCauseFieldWithoutReplay(v *Cause) *bool                               { return &v.withoutReplay }
func BridgeCauseMethodMarshalAPERBudget(v *Cause, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCauseMethodMarshalAPERBudgetValue(v *Cause, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCauseMethodMarshalAPERChanged(v *Cause, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCauseMethodMarshalAPERChangedValue(v *Cause, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCauseMethodMarshalAPERLegacy(v *Cause) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeCauseMethodMarshalAPERNewValue(v *Cause, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCauseMethodMarshalAPERPlanned(v *Cause, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCauseMethodMarshalAPERTo(v *Cause, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCauseMethodUnmarshalAPERFrom(v *Cause, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCauseMethodUnmarshalAPERLegacy(v *Cause, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCauseMethodUnmarshalAPERWithOptions(v *Cause, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCauseValueCodecFieldCapture(v *CauseValueCodec) *func(Cause, aper.DecodeState) (Cause, aper.Snapshot) {
	return &v.capture
}
func BridgeCauseValueCodecFieldCompare(v *CauseValueCodec) *func(Cause, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCauseValueCodecFieldContext(v *CauseValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeCauseValueCodecFieldDecode(v *CauseValueCodec) *func([]byte, aper.DecodeState) (Cause, error) {
	return &v.decode
}
func BridgeCauseValueCodecFieldEncode(v *CauseValueCodec) *func(Cause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCauseValueCodecFieldPath(v *CauseValueCodec) *aper.Path { return &v.path }
func BridgeCauseValueCodecMethodEncodeBudgetValue(v CauseValueCodec, a0 Cause, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCauseValueCodecMethodEncodeChanged(v CauseValueCodec, a0 Cause, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCdma2000OneXSRVCCInfoAPERValueFieldContext(v *Cdma2000OneXSRVCCInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCdma2000OneXSRVCCInfoAPERValueFieldReceived(v *Cdma2000OneXSRVCCInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCdma2000OneXSRVCCInfoAPERValueFieldReplay(v *Cdma2000OneXSRVCCInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCdma2000OneXSRVCCInfoAPERValueFieldWithoutReplay(v *Cdma2000OneXSRVCCInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCdma2000OneXSRVCCInfoFieldExtCount(v *Cdma2000OneXSRVCCInfo) *int64   { return &v.extCount }
func BridgeCdma2000OneXSRVCCInfoFieldExtData(v *Cdma2000OneXSRVCCInfo) *[][]byte { return &v.extData }
func BridgeCdma2000OneXSRVCCInfoFieldExtOrigin(v *Cdma2000OneXSRVCCInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCdma2000OneXSRVCCInfoFieldExtPresent(v *Cdma2000OneXSRVCCInfo) *[]bool {
	return &v.extPresent
}
func BridgeCdma2000OneXSRVCCInfoFieldExtWire(v *Cdma2000OneXSRVCCInfo) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCdma2000OneXSRVCCInfoFieldIEExtensionsIndef(v *Cdma2000OneXSRVCCInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCdma2000OneXSRVCCInfoFieldPerExtPadding(v *Cdma2000OneXSRVCCInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCdma2000OneXSRVCCInfoFieldPerPadding(v *Cdma2000OneXSRVCCInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCdma2000OneXSRVCCInfoFieldReceived(v *Cdma2000OneXSRVCCInfo) *bool { return &v.received }
func BridgeCdma2000OneXSRVCCInfoFieldReceivedAbsolute(v *Cdma2000OneXSRVCCInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeCdma2000OneXSRVCCInfoFieldReceivedBytes(v *Cdma2000OneXSRVCCInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCdma2000OneXSRVCCInfoFieldReceivedLocation(v *Cdma2000OneXSRVCCInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeCdma2000OneXSRVCCInfoFieldReplay(v *Cdma2000OneXSRVCCInfo) *aper.Snapshot {
	return &v.replay
}
func BridgeCdma2000OneXSRVCCInfoFieldStream(v *Cdma2000OneXSRVCCInfo) *aper.WireSpan {
	return &v.stream
}
func BridgeCdma2000OneXSRVCCInfoFieldWithoutReplay(v *Cdma2000OneXSRVCCInfo) *bool {
	return &v.withoutReplay
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERBudget(v *Cdma2000OneXSRVCCInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERBudgetValue(v *Cdma2000OneXSRVCCInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERChanged(v *Cdma2000OneXSRVCCInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERChangedValue(v *Cdma2000OneXSRVCCInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERLegacy(v *Cdma2000OneXSRVCCInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERNewValue(v *Cdma2000OneXSRVCCInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERPlanned(v *Cdma2000OneXSRVCCInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERTo(v *Cdma2000OneXSRVCCInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCdma2000OneXSRVCCInfoMethodUnmarshalAPERFrom(v *Cdma2000OneXSRVCCInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCdma2000OneXSRVCCInfoMethodUnmarshalAPERLegacy(v *Cdma2000OneXSRVCCInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCdma2000OneXSRVCCInfoMethodUnmarshalAPERWithOptions(v *Cdma2000OneXSRVCCInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldCapture(v *Cdma2000OneXSRVCCInfoValueCodec) *func(Cdma2000OneXSRVCCInfo, aper.DecodeState) (Cdma2000OneXSRVCCInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldCompare(v *Cdma2000OneXSRVCCInfoValueCodec) *func(Cdma2000OneXSRVCCInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldContext(v *Cdma2000OneXSRVCCInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldDecode(v *Cdma2000OneXSRVCCInfoValueCodec) *func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfo, error) {
	return &v.decode
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldEncode(v *Cdma2000OneXSRVCCInfoValueCodec) *func(Cdma2000OneXSRVCCInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldPath(v *Cdma2000OneXSRVCCInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeCdma2000OneXSRVCCInfoValueCodecMethodEncodeBudgetValue(v Cdma2000OneXSRVCCInfoValueCodec, a0 Cdma2000OneXSRVCCInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCdma2000OneXSRVCCInfoValueCodecMethodEncodeChanged(v Cdma2000OneXSRVCCInfoValueCodec, a0 Cdma2000OneXSRVCCInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellTypeAPERValueFieldContext(v *CellTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTypeAPERValueFieldReceived(v *CellTypeAPERValue) *aper.WireSpan { return &v.received }
func BridgeCellTypeAPERValueFieldReplay(v *CellTypeAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeCellTypeAPERValueFieldWithoutReplay(v *CellTypeAPERValue) *bool     { return &v.withoutReplay }
func BridgeCellTypeFieldExtCount(v *CellType) *int64                           { return &v.extCount }
func BridgeCellTypeFieldExtData(v *CellType) *[][]byte                         { return &v.extData }
func BridgeCellTypeFieldExtOrigin(v *CellType) *[]aper.OpaqueOrigin            { return &v.extOrigin }
func BridgeCellTypeFieldExtPresent(v *CellType) *[]bool                        { return &v.extPresent }
func BridgeCellTypeFieldExtWire(v *CellType) *[]aper.WireSpan                  { return &v.extWire }
func BridgeCellTypeFieldIEExtensionsIndef(v *CellType) *bool                   { return &v.iEExtensionsIndef }
func BridgeCellTypeFieldPerExtPadding(v *CellType) *[]aper.CompletePadding     { return &v.perExtPadding }
func BridgeCellTypeFieldPerPadding(v *CellType) *aper.FinalPadding             { return &v.perPadding }
func BridgeCellTypeFieldReceived(v *CellType) *bool                            { return &v.received }
func BridgeCellTypeFieldReceivedAbsolute(v *CellType) *bool                    { return &v.receivedAbsolute }
func BridgeCellTypeFieldReceivedBytes(v *CellType) *aper.WireSpan              { return &v.receivedBytes }
func BridgeCellTypeFieldReceivedLocation(v *CellType) *aper.Location           { return &v.receivedLocation }
func BridgeCellTypeFieldReplay(v *CellType) *aper.Snapshot                     { return &v.replay }
func BridgeCellTypeFieldStream(v *CellType) *aper.WireSpan                     { return &v.stream }
func BridgeCellTypeFieldWithoutReplay(v *CellType) *bool                       { return &v.withoutReplay }
func BridgeCellTypeMethodMarshalAPERBudget(v *CellType, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellTypeMethodMarshalAPERBudgetValue(v *CellType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellTypeMethodMarshalAPERChanged(v *CellType, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellTypeMethodMarshalAPERChangedValue(v *CellType, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellTypeMethodMarshalAPERLegacy(v *CellType) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeCellTypeMethodMarshalAPERNewValue(v *CellType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellTypeMethodMarshalAPERPlanned(v *CellType, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellTypeMethodMarshalAPERTo(v *CellType, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellTypeMethodUnmarshalAPERFrom(v *CellType, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellTypeMethodUnmarshalAPERLegacy(v *CellType, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellTypeMethodUnmarshalAPERWithOptions(v *CellType, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellTypeValueCodecFieldCapture(v *CellTypeValueCodec) *func(CellType, aper.DecodeState) (CellType, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTypeValueCodecFieldCompare(v *CellTypeValueCodec) *func(CellType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTypeValueCodecFieldContext(v *CellTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTypeValueCodecFieldDecode(v *CellTypeValueCodec) *func([]byte, aper.DecodeState) (CellType, error) {
	return &v.decode
}
func BridgeCellTypeValueCodecFieldEncode(v *CellTypeValueCodec) *func(CellType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTypeValueCodecFieldPath(v *CellTypeValueCodec) *aper.Path { return &v.path }
func BridgeCellTypeValueCodecMethodEncodeBudgetValue(v CellTypeValueCodec, a0 CellType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellTypeValueCodecMethodEncodeChanged(v CellTypeValueCodec, a0 CellType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellsToActivateListAPERValueFieldContext(v *CellsToActivateListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellsToActivateListAPERValueFieldReceived(v *CellsToActivateListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellsToActivateListAPERValueFieldReplay(v *CellsToActivateListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellsToActivateListAPERValueFieldWithoutReplay(v *CellsToActivateListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellsToActivateListItemAPERValueFieldContext(v *CellsToActivateListItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellsToActivateListItemAPERValueFieldReceived(v *CellsToActivateListItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellsToActivateListItemAPERValueFieldReplay(v *CellsToActivateListItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellsToActivateListItemAPERValueFieldWithoutReplay(v *CellsToActivateListItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellsToActivateListItemFieldExtCount(v *CellsToActivateListItem) *int64 {
	return &v.extCount
}
func BridgeCellsToActivateListItemFieldExtData(v *CellsToActivateListItem) *[][]byte {
	return &v.extData
}
func BridgeCellsToActivateListItemFieldExtOrigin(v *CellsToActivateListItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCellsToActivateListItemFieldExtPresent(v *CellsToActivateListItem) *[]bool {
	return &v.extPresent
}
func BridgeCellsToActivateListItemFieldExtWire(v *CellsToActivateListItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCellsToActivateListItemFieldPerExtPadding(v *CellsToActivateListItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCellsToActivateListItemFieldPerPadding(v *CellsToActivateListItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCellsToActivateListItemFieldReceived(v *CellsToActivateListItem) *bool { return &v.received }
func BridgeCellsToActivateListItemFieldReceivedAbsolute(v *CellsToActivateListItem) *bool {
	return &v.receivedAbsolute
}
func BridgeCellsToActivateListItemFieldReceivedBytes(v *CellsToActivateListItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellsToActivateListItemFieldReceivedLocation(v *CellsToActivateListItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellsToActivateListItemFieldReplay(v *CellsToActivateListItem) *aper.Snapshot {
	return &v.replay
}
func BridgeCellsToActivateListItemFieldStream(v *CellsToActivateListItem) *aper.WireSpan {
	return &v.stream
}
func BridgeCellsToActivateListItemFieldWithoutReplay(v *CellsToActivateListItem) *bool {
	return &v.withoutReplay
}
func BridgeCellsToActivateListItemMethodMarshalAPERBudget(v *CellsToActivateListItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellsToActivateListItemMethodMarshalAPERBudgetValue(v *CellsToActivateListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellsToActivateListItemMethodMarshalAPERChanged(v *CellsToActivateListItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellsToActivateListItemMethodMarshalAPERChangedValue(v *CellsToActivateListItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellsToActivateListItemMethodMarshalAPERLegacy(v *CellsToActivateListItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellsToActivateListItemMethodMarshalAPERNewValue(v *CellsToActivateListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellsToActivateListItemMethodMarshalAPERPlanned(v *CellsToActivateListItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellsToActivateListItemMethodMarshalAPERTo(v *CellsToActivateListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellsToActivateListItemMethodUnmarshalAPERFrom(v *CellsToActivateListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellsToActivateListItemMethodUnmarshalAPERLegacy(v *CellsToActivateListItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellsToActivateListItemMethodUnmarshalAPERWithOptions(v *CellsToActivateListItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellsToActivateListItemValueCodecFieldCapture(v *CellsToActivateListItemValueCodec) *func(CellsToActivateListItem, aper.DecodeState) (CellsToActivateListItem, aper.Snapshot) {
	return &v.capture
}
func BridgeCellsToActivateListItemValueCodecFieldCompare(v *CellsToActivateListItemValueCodec) *func(CellsToActivateListItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellsToActivateListItemValueCodecFieldContext(v *CellsToActivateListItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellsToActivateListItemValueCodecFieldDecode(v *CellsToActivateListItemValueCodec) *func([]byte, aper.DecodeState) (CellsToActivateListItem, error) {
	return &v.decode
}
func BridgeCellsToActivateListItemValueCodecFieldEncode(v *CellsToActivateListItemValueCodec) *func(CellsToActivateListItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellsToActivateListItemValueCodecFieldPath(v *CellsToActivateListItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellsToActivateListItemValueCodecMethodEncodeBudgetValue(v CellsToActivateListItemValueCodec, a0 CellsToActivateListItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellsToActivateListItemValueCodecMethodEncodeChanged(v CellsToActivateListItemValueCodec, a0 CellsToActivateListItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellsToActivateListValueCodecFieldCapture(v *CellsToActivateListValueCodec) *func(CellsToActivateList, aper.DecodeState) (CellsToActivateList, aper.Snapshot) {
	return &v.capture
}
func BridgeCellsToActivateListValueCodecFieldCompare(v *CellsToActivateListValueCodec) *func(CellsToActivateList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellsToActivateListValueCodecFieldContext(v *CellsToActivateListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellsToActivateListValueCodecFieldDecode(v *CellsToActivateListValueCodec) *func([]byte, aper.DecodeState) (CellsToActivateList, error) {
	return &v.decode
}
func BridgeCellsToActivateListValueCodecFieldEncode(v *CellsToActivateListValueCodec) *func(CellsToActivateList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellsToActivateListValueCodecFieldPath(v *CellsToActivateListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellsToActivateListValueCodecMethodEncodeBudgetValue(v CellsToActivateListValueCodec, a0 CellsToActivateList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellsToActivateListValueCodecMethodEncodeChanged(v CellsToActivateListValueCodec, a0 CellsToActivateList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEItemAPERValueFieldContext(v *CriticalityDiagnosticsIEItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEItemAPERValueFieldReceived(v *CriticalityDiagnosticsIEItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEItemAPERValueFieldReplay(v *CriticalityDiagnosticsIEItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEItemAPERValueFieldWithoutReplay(v *CriticalityDiagnosticsIEItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEItemFieldExtCount(v *CriticalityDiagnosticsIEItem) *int64 {
	return &v.extCount
}
func BridgeCriticalityDiagnosticsIEItemFieldExtData(v *CriticalityDiagnosticsIEItem) *[][]byte {
	return &v.extData
}
func BridgeCriticalityDiagnosticsIEItemFieldExtOrigin(v *CriticalityDiagnosticsIEItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCriticalityDiagnosticsIEItemFieldExtPresent(v *CriticalityDiagnosticsIEItem) *[]bool {
	return &v.extPresent
}
func BridgeCriticalityDiagnosticsIEItemFieldExtWire(v *CriticalityDiagnosticsIEItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCriticalityDiagnosticsIEItemFieldIEExtensionsIndef(v *CriticalityDiagnosticsIEItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCriticalityDiagnosticsIEItemFieldPerExtPadding(v *CriticalityDiagnosticsIEItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCriticalityDiagnosticsIEItemFieldPerPadding(v *CriticalityDiagnosticsIEItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsIEItemFieldReceived(v *CriticalityDiagnosticsIEItem) *bool {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEItemFieldReceivedAbsolute(v *CriticalityDiagnosticsIEItem) *bool {
	return &v.receivedAbsolute
}
func BridgeCriticalityDiagnosticsIEItemFieldReceivedBytes(v *CriticalityDiagnosticsIEItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsIEItemFieldReceivedLocation(v *CriticalityDiagnosticsIEItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeCriticalityDiagnosticsIEItemFieldReplay(v *CriticalityDiagnosticsIEItem) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEItemFieldStream(v *CriticalityDiagnosticsIEItem) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEItemFieldWithoutReplay(v *CriticalityDiagnosticsIEItem) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERBudget(v *CriticalityDiagnosticsIEItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERBudgetValue(v *CriticalityDiagnosticsIEItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERChanged(v *CriticalityDiagnosticsIEItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERChangedValue(v *CriticalityDiagnosticsIEItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERLegacy(v *CriticalityDiagnosticsIEItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERNewValue(v *CriticalityDiagnosticsIEItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERPlanned(v *CriticalityDiagnosticsIEItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERTo(v *CriticalityDiagnosticsIEItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEItemMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEItemMethodUnmarshalAPERLegacy(v *CriticalityDiagnosticsIEItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCriticalityDiagnosticsIEItemMethodUnmarshalAPERWithOptions(v *CriticalityDiagnosticsIEItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCriticalityDiagnosticsIEItemValueCodecFieldCapture(v *CriticalityDiagnosticsIEItemValueCodec) *func(CriticalityDiagnosticsIEItem, aper.DecodeState) (CriticalityDiagnosticsIEItem, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEItemValueCodecFieldCompare(v *CriticalityDiagnosticsIEItemValueCodec) *func(CriticalityDiagnosticsIEItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEItemValueCodecFieldContext(v *CriticalityDiagnosticsIEItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEItemValueCodecFieldDecode(v *CriticalityDiagnosticsIEItemValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEItem, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEItemValueCodecFieldEncode(v *CriticalityDiagnosticsIEItemValueCodec) *func(CriticalityDiagnosticsIEItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEItemValueCodecFieldPath(v *CriticalityDiagnosticsIEItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEItemValueCodecMethodEncodeBudgetValue(v CriticalityDiagnosticsIEItemValueCodec, a0 CriticalityDiagnosticsIEItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEItemValueCodecMethodEncodeChanged(v CriticalityDiagnosticsIEItemValueCodec, a0 CriticalityDiagnosticsIEItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldContext(v *CriticalityDiagnosticsIEListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldReceived(v *CriticalityDiagnosticsIEListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldReplay(v *CriticalityDiagnosticsIEListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldWithoutReplay(v *CriticalityDiagnosticsIEListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCapture(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, aper.DecodeState) (CriticalityDiagnosticsIEList, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCompare(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldContext(v *CriticalityDiagnosticsIEListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldDecode(v *CriticalityDiagnosticsIEListValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEList, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldEncode(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldPath(v *CriticalityDiagnosticsIEListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEListValueCodecMethodEncodeBudgetValue(v CriticalityDiagnosticsIEListValueCodec, a0 CriticalityDiagnosticsIEList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListValueCodecMethodEncodeChanged(v CriticalityDiagnosticsIEListValueCodec, a0 CriticalityDiagnosticsIEList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSRequestInfoAPERValueFieldContext(v *DAPSRequestInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSRequestInfoAPERValueFieldReceived(v *DAPSRequestInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSRequestInfoAPERValueFieldReplay(v *DAPSRequestInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSRequestInfoAPERValueFieldWithoutReplay(v *DAPSRequestInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSRequestInfoFieldExtCount(v *DAPSRequestInfo) *int64   { return &v.extCount }
func BridgeDAPSRequestInfoFieldExtData(v *DAPSRequestInfo) *[][]byte { return &v.extData }
func BridgeDAPSRequestInfoFieldExtOrigin(v *DAPSRequestInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDAPSRequestInfoFieldExtPresent(v *DAPSRequestInfo) *[]bool       { return &v.extPresent }
func BridgeDAPSRequestInfoFieldExtWire(v *DAPSRequestInfo) *[]aper.WireSpan { return &v.extWire }
func BridgeDAPSRequestInfoFieldIEExtensionsIndef(v *DAPSRequestInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeDAPSRequestInfoFieldPerExtPadding(v *DAPSRequestInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDAPSRequestInfoFieldPerPadding(v *DAPSRequestInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDAPSRequestInfoFieldReceived(v *DAPSRequestInfo) *bool         { return &v.received }
func BridgeDAPSRequestInfoFieldReceivedAbsolute(v *DAPSRequestInfo) *bool { return &v.receivedAbsolute }
func BridgeDAPSRequestInfoFieldReceivedBytes(v *DAPSRequestInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDAPSRequestInfoFieldReceivedLocation(v *DAPSRequestInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeDAPSRequestInfoFieldReplay(v *DAPSRequestInfo) *aper.Snapshot { return &v.replay }
func BridgeDAPSRequestInfoFieldStream(v *DAPSRequestInfo) *aper.WireSpan { return &v.stream }
func BridgeDAPSRequestInfoFieldWithoutReplay(v *DAPSRequestInfo) *bool   { return &v.withoutReplay }
func BridgeDAPSRequestInfoMethodMarshalAPERBudget(v *DAPSRequestInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDAPSRequestInfoMethodMarshalAPERBudgetValue(v *DAPSRequestInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDAPSRequestInfoMethodMarshalAPERChanged(v *DAPSRequestInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDAPSRequestInfoMethodMarshalAPERChangedValue(v *DAPSRequestInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDAPSRequestInfoMethodMarshalAPERLegacy(v *DAPSRequestInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDAPSRequestInfoMethodMarshalAPERNewValue(v *DAPSRequestInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDAPSRequestInfoMethodMarshalAPERPlanned(v *DAPSRequestInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDAPSRequestInfoMethodMarshalAPERTo(v *DAPSRequestInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSRequestInfoMethodUnmarshalAPERFrom(v *DAPSRequestInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSRequestInfoMethodUnmarshalAPERLegacy(v *DAPSRequestInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDAPSRequestInfoMethodUnmarshalAPERWithOptions(v *DAPSRequestInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDAPSRequestInfoValueCodecFieldCapture(v *DAPSRequestInfoValueCodec) *func(DAPSRequestInfo, aper.DecodeState) (DAPSRequestInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSRequestInfoValueCodecFieldCompare(v *DAPSRequestInfoValueCodec) *func(DAPSRequestInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSRequestInfoValueCodecFieldContext(v *DAPSRequestInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSRequestInfoValueCodecFieldDecode(v *DAPSRequestInfoValueCodec) *func([]byte, aper.DecodeState) (DAPSRequestInfo, error) {
	return &v.decode
}
func BridgeDAPSRequestInfoValueCodecFieldEncode(v *DAPSRequestInfoValueCodec) *func(DAPSRequestInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSRequestInfoValueCodecFieldPath(v *DAPSRequestInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSRequestInfoValueCodecMethodEncodeBudgetValue(v DAPSRequestInfoValueCodec, a0 DAPSRequestInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSRequestInfoValueCodecMethodEncodeChanged(v DAPSRequestInfoValueCodec, a0 DAPSRequestInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoAPERValueFieldContext(v *DAPSResponseInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoAPERValueFieldReceived(v *DAPSResponseInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoAPERValueFieldReplay(v *DAPSResponseInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoAPERValueFieldWithoutReplay(v *DAPSResponseInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoFieldExtCount(v *DAPSResponseInfo) *int64   { return &v.extCount }
func BridgeDAPSResponseInfoFieldExtData(v *DAPSResponseInfo) *[][]byte { return &v.extData }
func BridgeDAPSResponseInfoFieldExtOrigin(v *DAPSResponseInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDAPSResponseInfoFieldExtPresent(v *DAPSResponseInfo) *[]bool       { return &v.extPresent }
func BridgeDAPSResponseInfoFieldExtWire(v *DAPSResponseInfo) *[]aper.WireSpan { return &v.extWire }
func BridgeDAPSResponseInfoFieldIEExtensionsIndef(v *DAPSResponseInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeDAPSResponseInfoFieldPerExtPadding(v *DAPSResponseInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDAPSResponseInfoFieldPerPadding(v *DAPSResponseInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDAPSResponseInfoFieldReceived(v *DAPSResponseInfo) *bool { return &v.received }
func BridgeDAPSResponseInfoFieldReceivedAbsolute(v *DAPSResponseInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeDAPSResponseInfoFieldReceivedBytes(v *DAPSResponseInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDAPSResponseInfoFieldReceivedLocation(v *DAPSResponseInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeDAPSResponseInfoFieldReplay(v *DAPSResponseInfo) *aper.Snapshot { return &v.replay }
func BridgeDAPSResponseInfoFieldStream(v *DAPSResponseInfo) *aper.WireSpan { return &v.stream }
func BridgeDAPSResponseInfoFieldWithoutReplay(v *DAPSResponseInfo) *bool   { return &v.withoutReplay }
func BridgeDAPSResponseInfoItemAPERValueFieldContext(v *DAPSResponseInfoItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoItemAPERValueFieldReceived(v *DAPSResponseInfoItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoItemAPERValueFieldReplay(v *DAPSResponseInfoItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoItemAPERValueFieldWithoutReplay(v *DAPSResponseInfoItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoItemFieldExtCount(v *DAPSResponseInfoItem) *int64   { return &v.extCount }
func BridgeDAPSResponseInfoItemFieldExtData(v *DAPSResponseInfoItem) *[][]byte { return &v.extData }
func BridgeDAPSResponseInfoItemFieldExtOrigin(v *DAPSResponseInfoItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDAPSResponseInfoItemFieldExtPresent(v *DAPSResponseInfoItem) *[]bool { return &v.extPresent }
func BridgeDAPSResponseInfoItemFieldExtWire(v *DAPSResponseInfoItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeDAPSResponseInfoItemFieldIEExtensionsIndef(v *DAPSResponseInfoItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeDAPSResponseInfoItemFieldPerExtPadding(v *DAPSResponseInfoItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDAPSResponseInfoItemFieldPerPadding(v *DAPSResponseInfoItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDAPSResponseInfoItemFieldReceived(v *DAPSResponseInfoItem) *bool { return &v.received }
func BridgeDAPSResponseInfoItemFieldReceivedAbsolute(v *DAPSResponseInfoItem) *bool {
	return &v.receivedAbsolute
}
func BridgeDAPSResponseInfoItemFieldReceivedBytes(v *DAPSResponseInfoItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDAPSResponseInfoItemFieldReceivedLocation(v *DAPSResponseInfoItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeDAPSResponseInfoItemFieldReplay(v *DAPSResponseInfoItem) *aper.Snapshot { return &v.replay }
func BridgeDAPSResponseInfoItemFieldStream(v *DAPSResponseInfoItem) *aper.WireSpan { return &v.stream }
func BridgeDAPSResponseInfoItemFieldWithoutReplay(v *DAPSResponseInfoItem) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERBudget(v *DAPSResponseInfoItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERBudgetValue(v *DAPSResponseInfoItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERChanged(v *DAPSResponseInfoItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERChangedValue(v *DAPSResponseInfoItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERLegacy(v *DAPSResponseInfoItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERNewValue(v *DAPSResponseInfoItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERPlanned(v *DAPSResponseInfoItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDAPSResponseInfoItemMethodMarshalAPERTo(v *DAPSResponseInfoItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSResponseInfoItemMethodUnmarshalAPERFrom(v *DAPSResponseInfoItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSResponseInfoItemMethodUnmarshalAPERLegacy(v *DAPSResponseInfoItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDAPSResponseInfoItemMethodUnmarshalAPERWithOptions(v *DAPSResponseInfoItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDAPSResponseInfoItemValueCodecFieldCapture(v *DAPSResponseInfoItemValueCodec) *func(DAPSResponseInfoItem, aper.DecodeState) (DAPSResponseInfoItem, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoItemValueCodecFieldCompare(v *DAPSResponseInfoItemValueCodec) *func(DAPSResponseInfoItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoItemValueCodecFieldContext(v *DAPSResponseInfoItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoItemValueCodecFieldDecode(v *DAPSResponseInfoItemValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoItem, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoItemValueCodecFieldEncode(v *DAPSResponseInfoItemValueCodec) *func(DAPSResponseInfoItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoItemValueCodecFieldPath(v *DAPSResponseInfoItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoItemValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoItemValueCodec, a0 DAPSResponseInfoItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoItemValueCodecMethodEncodeChanged(v DAPSResponseInfoItemValueCodec, a0 DAPSResponseInfoItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoListAPERValueFieldContext(v *DAPSResponseInfoListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListAPERValueFieldReceived(v *DAPSResponseInfoListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoListAPERValueFieldReplay(v *DAPSResponseInfoListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListAPERValueFieldWithoutReplay(v *DAPSResponseInfoListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListDAPSResponseInfoItemIEBindingFieldCodec(v *DAPSResponseInfoListDAPSResponseInfoItemIEBinding) *DAPSResponseInfoItemValueCodec {
	return &v.codec
}
func BridgeDAPSResponseInfoListDAPSResponseInfoItemIEBindingFieldGet(v *DAPSResponseInfoListDAPSResponseInfoItemIEBinding) *func(*DAPSResponseInfoListIEValue) (*DAPSResponseInfoItem, bool) {
	return &v.get
}
func BridgeDAPSResponseInfoListDAPSResponseInfoItemIEBindingFieldInfo(v *DAPSResponseInfoListDAPSResponseInfoItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDAPSResponseInfoListDAPSResponseInfoItemIEBindingFieldInject(v *DAPSResponseInfoListDAPSResponseInfoItemIEBinding) *func(DAPSResponseInfoItem) DAPSResponseInfoListIEValue {
	return &v.inject
}
func BridgeDAPSResponseInfoListIEContainerAPERValueFieldContext(v *DAPSResponseInfoListIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEContainerAPERValueFieldReceived(v *DAPSResponseInfoListIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoListIEContainerAPERValueFieldReplay(v *DAPSResponseInfoListIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEContainerAPERValueFieldWithoutReplay(v *DAPSResponseInfoListIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldCapture(v *DAPSResponseInfoListIEContainerValueCodec) *func(DAPSResponseInfoListIEContainer, aper.DecodeState) (DAPSResponseInfoListIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldCompare(v *DAPSResponseInfoListIEContainerValueCodec) *func(DAPSResponseInfoListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldContext(v *DAPSResponseInfoListIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(v *DAPSResponseInfoListIEContainerValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEContainer, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(v *DAPSResponseInfoListIEContainerValueCodec) *func(DAPSResponseInfoListIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldPath(v *DAPSResponseInfoListIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEContainerValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoListIEContainerValueCodec, a0 DAPSResponseInfoListIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoListIEContainerValueCodecMethodEncodeChanged(v DAPSResponseInfoListIEContainerValueCodec, a0 DAPSResponseInfoListIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoListIEFieldAPERValueFieldContext(v *DAPSResponseInfoListIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEFieldAPERValueFieldReceived(v *DAPSResponseInfoListIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoListIEFieldAPERValueFieldReplay(v *DAPSResponseInfoListIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEFieldAPERValueFieldWithoutReplay(v *DAPSResponseInfoListIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListIEFieldFieldReceived(v *DAPSResponseInfoListIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeDAPSResponseInfoListIEFieldFieldReplay(v *DAPSResponseInfoListIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEFieldFieldStream(v *DAPSResponseInfoListIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeDAPSResponseInfoListIEFieldFieldWithoutReplay(v *DAPSResponseInfoListIEField) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(v *DAPSResponseInfoListIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(v *DAPSResponseInfoListIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldCapture(v *DAPSResponseInfoListIEFieldValueCodec) *func(DAPSResponseInfoListIEField, aper.DecodeState) (DAPSResponseInfoListIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldCompare(v *DAPSResponseInfoListIEFieldValueCodec) *func(DAPSResponseInfoListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldContext(v *DAPSResponseInfoListIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldDecode(v *DAPSResponseInfoListIEFieldValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEField, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldEncode(v *DAPSResponseInfoListIEFieldValueCodec) *func(DAPSResponseInfoListIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldPath(v *DAPSResponseInfoListIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEFieldValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoListIEFieldValueCodec, a0 DAPSResponseInfoListIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoListIEFieldValueCodecMethodEncodeChanged(v DAPSResponseInfoListIEFieldValueCodec, a0 DAPSResponseInfoListIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoListIETableMethodInfoDAPSResponseInfoItem(v DAPSResponseInfoListIETable) s00.FieldInfo {
	return v.infoDAPSResponseInfoItem()
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListAPERValueFieldContext(v *DAPSResponseInfoListIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListAPERValueFieldReceived(v *DAPSResponseInfoListIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListAPERValueFieldReplay(v *DAPSResponseInfoListIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *DAPSResponseInfoListIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCapture(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueERABIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCompare(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldContext(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldDecode(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldEncode(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldPath(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoListIEValueERABIEContainerListValueCodec, a0 DAPSResponseInfoListIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecMethodEncodeChanged(v DAPSResponseInfoListIEValueERABIEContainerListValueCodec, a0 DAPSResponseInfoListIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoListIEValueFieldId(v *DAPSResponseInfoListIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeDAPSResponseInfoListIEValueFieldIsOpaque(v *DAPSResponseInfoListIEValue) *bool {
	return &v.isOpaque
}
func BridgeDAPSResponseInfoListIEValueFieldOpaque(v *DAPSResponseInfoListIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeDAPSResponseInfoListIEValueFieldReceived(v *DAPSResponseInfoListIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoListIEValueFieldReplay(v *DAPSResponseInfoListIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEValueFieldRowDAPSResponseInfoItem(v *DAPSResponseInfoListIEValue) **DAPSResponseInfoItem {
	return &v.rowDAPSResponseInfoItem
}
func BridgeDAPSResponseInfoListIEValueMethodCaptureSemantics(v DAPSResponseInfoListIEValue, a0 aper.SemanticCapture) DAPSResponseInfoListIEValue {
	return v.captureSemantics(a0)
}
func BridgeDAPSResponseInfoListIEValueMethodCompareSemantics(v DAPSResponseInfoListIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeDAPSResponseInfoListIEValueMethodDecode(v DAPSResponseInfoListIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (DAPSResponseInfoListIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeDAPSResponseInfoListIEValueMethodEncode(v DAPSResponseInfoListIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeDAPSResponseInfoListIEValueMethodEncodeFresh(v DAPSResponseInfoListIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeDAPSResponseInfoListIEValueMethodMatchesID(v DAPSResponseInfoListIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeDAPSResponseInfoListIEValueMethodReason(v DAPSResponseInfoListIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeDAPSResponseInfoListIEValueMethodRule(v DAPSResponseInfoListIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec, a0 DAPSResponseInfoListIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec, a0 DAPSResponseInfoListIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListAPERValueFieldContext(v *DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListAPERValueFieldReceived(v *DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListAPERValueFieldReplay(v *DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCapture(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCompare(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldContext(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldDecode(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldEncode(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldPath(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec, a0 DAPSResponseInfoListIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec, a0 DAPSResponseInfoListIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoListValueCodecFieldCapture(v *DAPSResponseInfoListValueCodec) *func(DAPSResponseInfoList, aper.DecodeState) (DAPSResponseInfoList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListValueCodecFieldCompare(v *DAPSResponseInfoListValueCodec) *func(DAPSResponseInfoList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListValueCodecFieldContext(v *DAPSResponseInfoListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListValueCodecFieldDecode(v *DAPSResponseInfoListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListValueCodecFieldEncode(v *DAPSResponseInfoListValueCodec) *func(DAPSResponseInfoList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListValueCodecFieldPath(v *DAPSResponseInfoListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoListValueCodec, a0 DAPSResponseInfoList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoListValueCodecMethodEncodeChanged(v DAPSResponseInfoListValueCodec, a0 DAPSResponseInfoList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDAPSResponseInfoMethodMarshalAPERBudget(v *DAPSResponseInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDAPSResponseInfoMethodMarshalAPERBudgetValue(v *DAPSResponseInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDAPSResponseInfoMethodMarshalAPERChanged(v *DAPSResponseInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDAPSResponseInfoMethodMarshalAPERChangedValue(v *DAPSResponseInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoMethodMarshalAPERLegacy(v *DAPSResponseInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDAPSResponseInfoMethodMarshalAPERNewValue(v *DAPSResponseInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDAPSResponseInfoMethodMarshalAPERPlanned(v *DAPSResponseInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDAPSResponseInfoMethodMarshalAPERTo(v *DAPSResponseInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSResponseInfoMethodUnmarshalAPERFrom(v *DAPSResponseInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSResponseInfoMethodUnmarshalAPERLegacy(v *DAPSResponseInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDAPSResponseInfoMethodUnmarshalAPERWithOptions(v *DAPSResponseInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDAPSResponseInfoValueCodecFieldCapture(v *DAPSResponseInfoValueCodec) *func(DAPSResponseInfo, aper.DecodeState) (DAPSResponseInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoValueCodecFieldCompare(v *DAPSResponseInfoValueCodec) *func(DAPSResponseInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoValueCodecFieldContext(v *DAPSResponseInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoValueCodecFieldDecode(v *DAPSResponseInfoValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfo, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoValueCodecFieldEncode(v *DAPSResponseInfoValueCodec) *func(DAPSResponseInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoValueCodecFieldPath(v *DAPSResponseInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoValueCodecMethodEncodeBudgetValue(v DAPSResponseInfoValueCodec, a0 DAPSResponseInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDAPSResponseInfoValueCodecMethodEncodeChanged(v DAPSResponseInfoValueCodec, a0 DAPSResponseInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDLCOUNTPDCPSNlengthFieldPerOpenTypePadding(v *DLCOUNTPDCPSNlength) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeDLCOUNTPDCPSNlengthFieldPerPadding(v *DLCOUNTPDCPSNlength) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeDLCOUNTPDCPSNlengthFieldReceived(v *DLCOUNTPDCPSNlength) *bool { return &v.received }
func BridgeDLCOUNTPDCPSNlengthFieldReceivedAbsolute(v *DLCOUNTPDCPSNlength) *bool {
	return &v.receivedAbsolute
}
func BridgeDLCOUNTPDCPSNlengthFieldReceivedBytes(v *DLCOUNTPDCPSNlength) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDLCOUNTPDCPSNlengthFieldReceivedLocation(v *DLCOUNTPDCPSNlength) *aper.Location {
	return &v.receivedLocation
}
func BridgeDLCOUNTPDCPSNlengthFieldReplay(v *DLCOUNTPDCPSNlength) *aper.Snapshot { return &v.replay }
func BridgeDLCOUNTPDCPSNlengthFieldStream(v *DLCOUNTPDCPSNlength) *aper.WireSpan { return &v.stream }
func BridgeDLCOUNTPDCPSNlengthFieldWithoutReplay(v *DLCOUNTPDCPSNlength) *bool {
	return &v.withoutReplay
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget(v *DLCOUNTPDCPSNlength, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudgetValue(v *DLCOUNTPDCPSNlength, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERChanged(v *DLCOUNTPDCPSNlength, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERChangedValue(v *DLCOUNTPDCPSNlength, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERLegacy(v *DLCOUNTPDCPSNlength) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERNewValue(v *DLCOUNTPDCPSNlength, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERPlanned(v *DLCOUNTPDCPSNlength, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERTo(v *DLCOUNTPDCPSNlength, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDLCOUNTPDCPSNlengthMethodUnmarshalAPERFrom(v *DLCOUNTPDCPSNlength, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDLCOUNTPDCPSNlengthMethodUnmarshalAPERLegacy(v *DLCOUNTPDCPSNlength, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDLCOUNTPDCPSNlengthMethodUnmarshalAPERWithOptions(v *DLCOUNTPDCPSNlength, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 179:
		if value, ok := v.AsULCOUNTValueExtended(); ok {
			return value, true
		}
	case 180:
		if value, ok := v.AsDLCOUNTValueExtended(); ok {
			return value, true
		}
	case 181:
		if value, ok := v.AsReceiveStatusOfULPDCPSDUsExtended(); ok {
			return value, true
		}
	case 217:
		if value, ok := v.AsULCOUNTValuePDCPSNlength18(); ok {
			return value, true
		}
	case 218:
		if value, ok := v.AsDLCOUNTValuePDCPSNlength18(); ok {
			return value, true
		}
	case 219:
		if value, ok := v.AsReceiveStatusOfULPDCPSDUsPDCPSNlength18(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *DAPSResponseInfoListIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 319:
		if value, ok := v.AsDAPSResponseInfoItem(); ok {
			return value, true
		}
	}
	return nil, false
}
