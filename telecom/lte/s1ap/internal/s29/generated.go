// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s29 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s29

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func BridgeERABInformationListIEValueCaptureS1APProtocolIESingleContainer(v *ERABInformationListIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABInformationListIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABInformationListIEValueCompareS1APProtocolIESingleContainer(v *ERABInformationListIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABInformationListIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s28.ERABInformationListItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s28.ERABInformationListItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionContainer(v *s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCompareS1APProtocolExtensionContainer(v *s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *ERABToBeSetupItemHOReqExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueCompareS1APProtocolExtensionContainer(v *ERABToBeSetupItemHOReqExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemHOReqExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIESingleContainer(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIESingleContainer(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIESingleContainer(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIESingleContainer(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ERABInformationListIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABInformationListIEValue].
type ERABInformationListIEValueProtocolIESingleContainer = ERABInformationListIEField

// ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer = ERABToBeSetupItemHOReqIEField

// ERABToBeSetupItemHOReqExtIEsExtContainer is the concrete ProtocolExtensionContainer[ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsExtContainer []ERABToBeSetupItemHOReqExtIEsExtField

// ERABToBeSwitchedDLItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ERABToBeSwitchedDLItemExtIEsValue].
type ERABToBeSwitchedDLItemExtIEsExtContainer []ERABToBeSwitchedDLItemExtIEsExtField

// ERABToBeUpdatedItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemIEValueProtocolIESingleContainer = ERABToBeUpdatedItemIEField

// ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer = ERABToBeSetupItemBearerSUReqIEField

// ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer = ERABToBeSetupItemCtxtSUReqIEField

// ERABToBeSetupItemHOReqExtIEsExtField is the concrete ProtocolExtensionField[ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeSetupItemHOReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqExtIEsExtField) WithoutReplay() ERABToBeSetupItemHOReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemHOReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemHOReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemHOReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemHOReqExtIEsExtField{}
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
	var zero ERABToBeSetupItemHOReqExtIEsValue

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

// ERABToBeSwitchedDLItemExtIEsExtField is the concrete ProtocolExtensionField[ERABToBeSwitchedDLItemExtIEsValue].
type ERABToBeSwitchedDLItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeSwitchedDLItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemExtIEsExtField) WithoutReplay() ERABToBeSwitchedDLItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSwitchedDLItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSwitchedDLItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSwitchedDLItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedDLItemExtIEsExtField{}
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
	var zero ERABToBeSwitchedDLItemExtIEsValue

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

// ERABInformationListERABInformationListItemIEBinding is the concrete IEBinding[ERABInformationListItem, ERABInformationListIEValue].
type ERABInformationListERABInformationListItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABInformationListItemValueCodec
	inject func(ERABInformationListItem,

	) ERABInformationListIEValue

	get func(*ERABInformationListIEValue,

	) (*ERABInformationListItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABInformationListERABInformationListItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABInformationListERABInformationListItemIEBinding) Codec() ERABInformationListItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABInformationListERABInformationListItemIEBinding) New(value ERABInformationListItem,

) (ERABInformationListIEField, error) {
	if b.inject == nil {
		return ERABInformationListIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABInformationListIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABInformationListIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABInformationListIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABInformationListERABInformationListItemIEBinding) Get(field *ERABInformationListIEField) (*ERABInformationListItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABInformationListItemValueCodec is the concrete ValueCodec[ERABInformationListItem].
type ERABInformationListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListItem,

		error)
	encode func(ERABInformationListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListItem, aper.DecodeState,

	) (ERABInformationListItem, aper.Snapshot,

	)
	compare func(ERABInformationListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListItemValueCodec) New(value ERABInformationListItem,

) (ERABInformationListItemAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListItemValueCodec) EncodeAPER(value ERABInformationListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListItemValueCodec) encodeBudgetValue(value ERABInformationListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListItemValueCodec) encodeChanged(value ERABInformationListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListIEField is the concrete ProtocolIEField[ERABInformationListIEValue].
type ERABInformationListIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABInformationListIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListIEField) WithoutReplay() ERABInformationListIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABInformationListIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABInformationListIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABInformationListIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABInformationListIEField{}
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
	var zero ERABInformationListIEValue

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

// ERABInformationListItemExtIEsSecurityIndicationExtBinding is the concrete ExtensionBinding[SecurityIndication, ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(s28.SecurityIndication,

	) s28.ERABInformationListItemExtIEsValue

	get func(*s28.ERABInformationListItemExtIEsValue,

	) (*s28.SecurityIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABInformationListItemExtIEsSecurityIndicationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABInformationListItemExtIEsSecurityIndicationExtBinding) Codec() SecurityIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABInformationListItemExtIEsSecurityIndicationExtBinding) New(value s28.SecurityIndication,

) (s28.ERABInformationListItemExtIEsExtField, error) {
	if b.inject == nil {
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return s28.ERABInformationListItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABInformationListItemExtIEsSecurityIndicationExtBinding) Get(field *s28.ERABInformationListItemExtIEsExtField) (*s28.SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SecurityIndicationValueCodec is the concrete ValueCodec[SecurityIndication].
type SecurityIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s28.SecurityIndication,

		error)
	encode func(s28.SecurityIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s28.SecurityIndication, aper.DecodeState,

	) (s28.SecurityIndication, aper.Snapshot,

	)
	compare func(s28.SecurityIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityIndicationValueCodec) New(value s28.SecurityIndication,

) (SecurityIndicationAPERValue, error) {
	if c.encode == nil {
		return SecurityIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityIndicationValueCodec) EncodeAPER(value SecurityIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecurityIndicationValueCodec) encodeBudgetValue(value s28.SecurityIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityIndicationValueCodec) encodeChanged(value s28.SecurityIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupListBearerSUReqValueCodec is the concrete ValueCodec[ERABToBeSetupListBearerSUReq].
type ERABToBeSetupListBearerSUReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupListBearerSUReq,

		error)
	encode func(ERABToBeSetupListBearerSUReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupListBearerSUReq, aper.DecodeState,

	) (ERABToBeSetupListBearerSUReq, aper.Snapshot,

	)
	compare func(ERABToBeSetupListBearerSUReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupListBearerSUReqValueCodec) New(value ERABToBeSetupListBearerSUReq,

) (ERABToBeSetupListBearerSUReqAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupListBearerSUReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupListBearerSUReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupListBearerSUReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupListBearerSUReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupListBearerSUReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupListBearerSUReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupListBearerSUReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupListBearerSUReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupListBearerSUReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupListBearerSUReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupListBearerSUReqValueCodec) EncodeAPER(value ERABToBeSetupListBearerSUReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupListBearerSUReqValueCodec) encodeBudgetValue(value ERABToBeSetupListBearerSUReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupListBearerSUReqValueCodec) encodeChanged(value ERABToBeSetupListBearerSUReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding is the concrete ExtensionBinding[SecurityIndication, ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(s28.SecurityIndication,

	) s28.ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*s28.ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*s28.SecurityIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) Codec() SecurityIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) New(value s28.SecurityIndication,

) (s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) Get(field *s28.ERABToBeSetupItemBearerSUReqExtIEsExtField) (*s28.SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding is the concrete IEBinding[ERABToBeSetupItemBearerSUReq, ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeSetupItemBearerSUReqValueCodec
	inject func(ERABToBeSetupItemBearerSUReq,

	) ERABToBeSetupItemBearerSUReqIEValue

	get func(*ERABToBeSetupItemBearerSUReqIEValue,

	) (*ERABToBeSetupItemBearerSUReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) Codec() ERABToBeSetupItemBearerSUReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) New(value ERABToBeSetupItemBearerSUReq,

) (ERABToBeSetupItemBearerSUReqIEField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) Get(field *ERABToBeSetupItemBearerSUReqIEField) (*ERABToBeSetupItemBearerSUReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeSetupItemBearerSUReqValueCodec is the concrete ValueCodec[ERABToBeSetupItemBearerSUReq].
type ERABToBeSetupItemBearerSUReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReq,

		error)
	encode func(ERABToBeSetupItemBearerSUReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReq, aper.DecodeState,

	) (ERABToBeSetupItemBearerSUReq, aper.Snapshot,

	)
	compare func(ERABToBeSetupItemBearerSUReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqValueCodec) New(value ERABToBeSetupItemBearerSUReq,

) (ERABToBeSetupItemBearerSUReqAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqIEField is the concrete ProtocolIEField[ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemBearerSUReqIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqIEField) WithoutReplay() ERABToBeSetupItemBearerSUReqIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemBearerSUReqIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemBearerSUReqIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemBearerSUReqIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemBearerSUReqIEField{}
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
	var zero ERABToBeSetupItemBearerSUReqIEValue

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

// ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding is the concrete ExtensionBinding[SecurityIndication, ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(s28.SecurityIndication,

	) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*s28.ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*s28.SecurityIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) Codec() SecurityIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) New(value s28.SecurityIndication,

) (s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) Get(field *s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*s28.SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding is the concrete IEBinding[ERABToBeSetupItemCtxtSUReq, ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeSetupItemCtxtSUReqValueCodec
	inject func(ERABToBeSetupItemCtxtSUReq,

	) ERABToBeSetupItemCtxtSUReqIEValue

	get func(*ERABToBeSetupItemCtxtSUReqIEValue,

	) (*ERABToBeSetupItemCtxtSUReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) Codec() ERABToBeSetupItemCtxtSUReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) New(value ERABToBeSetupItemCtxtSUReq,

) (ERABToBeSetupItemCtxtSUReqIEField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) Get(field *ERABToBeSetupItemCtxtSUReqIEField) (*ERABToBeSetupItemCtxtSUReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeSetupItemCtxtSUReqValueCodec is the concrete ValueCodec[ERABToBeSetupItemCtxtSUReq].
type ERABToBeSetupItemCtxtSUReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReq,

		error)
	encode func(ERABToBeSetupItemCtxtSUReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReq, aper.DecodeState,

	) (ERABToBeSetupItemCtxtSUReq, aper.Snapshot,

	)
	compare func(ERABToBeSetupItemCtxtSUReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqValueCodec) New(value ERABToBeSetupItemCtxtSUReq,

) (ERABToBeSetupItemCtxtSUReqAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqIEField is the concrete ProtocolIEField[ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemCtxtSUReqIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqIEField) WithoutReplay() ERABToBeSetupItemCtxtSUReqIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemCtxtSUReqIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemCtxtSUReqIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemCtxtSUReqIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemCtxtSUReqIEField{}
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
	var zero ERABToBeSetupItemCtxtSUReqIEValue

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

// ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding is the concrete ExtensionBinding[DataForwardingNotPossible, ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.DataForwardingNotPossibleValueCodec
	inject func(s00.DataForwardingNotPossible,

	) ERABToBeSetupItemHOReqExtIEsValue

	get func(*ERABToBeSetupItemHOReqExtIEsValue,

	) (*s00.DataForwardingNotPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) Codec() s00.DataForwardingNotPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) New(value s00.DataForwardingNotPossible,

) (ERABToBeSetupItemHOReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDataForwardingNotPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemHOReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) Get(field *ERABToBeSetupItemHOReqExtIEsExtField) (*s00.DataForwardingNotPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding is the concrete ExtensionBinding[BearerType, ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.BearerTypeValueCodec
	inject func(s00.BearerType,

	) ERABToBeSetupItemHOReqExtIEsValue

	get func(*ERABToBeSetupItemHOReqExtIEsValue,

	) (*s00.BearerType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) Codec() s00.BearerTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) New(value s00.BearerType,

) (ERABToBeSetupItemHOReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeBearerTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemHOReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) Get(field *ERABToBeSetupItemHOReqExtIEsExtField) (*s00.BearerType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding is the concrete ExtensionBinding[EthernetType, ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.EthernetTypeValueCodec
	inject func(s00.EthernetType,

	) ERABToBeSetupItemHOReqExtIEsValue

	get func(*ERABToBeSetupItemHOReqExtIEsValue,

	) (*s00.EthernetType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) Codec() s00.EthernetTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) New(value s00.EthernetType,

) (ERABToBeSetupItemHOReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEthernetTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemHOReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) Get(field *ERABToBeSetupItemHOReqExtIEsExtField) (*s00.EthernetType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding is the concrete ExtensionBinding[SecurityIndication, ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(s28.SecurityIndication,

	) ERABToBeSetupItemHOReqExtIEsValue

	get func(*ERABToBeSetupItemHOReqExtIEsValue,

	) (*s28.SecurityIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) Codec() SecurityIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) New(value s28.SecurityIndication,

) (ERABToBeSetupItemHOReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemHOReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) Get(field *ERABToBeSetupItemHOReqExtIEsExtField) (*s28.SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding is the concrete IEBinding[ERABToBeSetupItemHOReq, ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeSetupItemHOReqValueCodec
	inject func(ERABToBeSetupItemHOReq,

	) ERABToBeSetupItemHOReqIEValue

	get func(*ERABToBeSetupItemHOReqIEValue,

	) (*ERABToBeSetupItemHOReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) Codec() ERABToBeSetupItemHOReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) New(value ERABToBeSetupItemHOReq,

) (ERABToBeSetupItemHOReqIEField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemHOReqIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemHOReqIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemHOReqIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) Get(field *ERABToBeSetupItemHOReqIEField) (*ERABToBeSetupItemHOReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeSetupItemHOReqValueCodec is the concrete ValueCodec[ERABToBeSetupItemHOReq].
type ERABToBeSetupItemHOReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReq,

		error)
	encode func(ERABToBeSetupItemHOReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReq, aper.DecodeState,

	) (ERABToBeSetupItemHOReq, aper.Snapshot,

	)
	compare func(ERABToBeSetupItemHOReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqValueCodec) New(value ERABToBeSetupItemHOReq,

) (ERABToBeSetupItemHOReqAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqValueCodec) encodeChanged(value ERABToBeSetupItemHOReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqIEField is the concrete ProtocolIEField[ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemHOReqIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqIEField) WithoutReplay() ERABToBeSetupItemHOReqIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemHOReqIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemHOReqIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemHOReqIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemHOReqIEField{}
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
	var zero ERABToBeSetupItemHOReqIEValue

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

// ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding is the concrete ExtensionBinding[SecurityIndication, ERABToBeSwitchedDLItemExtIEsValue].
type ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(s28.SecurityIndication,

	) ERABToBeSwitchedDLItemExtIEsValue

	get func(*ERABToBeSwitchedDLItemExtIEsValue,

	) (*s28.SecurityIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) Codec() SecurityIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) New(value s28.SecurityIndication,

) (ERABToBeSwitchedDLItemExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSwitchedDLItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) Get(field *ERABToBeSwitchedDLItemExtIEsExtField) (*s28.SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding is the concrete IEBinding[ERABToBeUpdatedItem, ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeUpdatedItemValueCodec
	inject func(ERABToBeUpdatedItem,

	) ERABToBeUpdatedItemIEValue

	get func(*ERABToBeUpdatedItemIEValue,

	) (*ERABToBeUpdatedItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) Codec() ERABToBeUpdatedItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) New(value ERABToBeUpdatedItem,

) (ERABToBeUpdatedItemIEField, error) {
	if b.inject == nil {
		return ERABToBeUpdatedItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeUpdatedItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeUpdatedItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) Get(field *ERABToBeUpdatedItemIEField) (*ERABToBeUpdatedItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeUpdatedItemValueCodec is the concrete ValueCodec[ERABToBeUpdatedItem].
type ERABToBeUpdatedItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItem,

		error)
	encode func(ERABToBeUpdatedItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItem, aper.DecodeState,

	) (ERABToBeUpdatedItem, aper.Snapshot,

	)
	compare func(ERABToBeUpdatedItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemValueCodec) New(value ERABToBeUpdatedItem,

) (ERABToBeUpdatedItemAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemValueCodec) EncodeAPER(value ERABToBeUpdatedItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemValueCodec) encodeBudgetValue(value ERABToBeUpdatedItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemValueCodec) encodeChanged(value ERABToBeUpdatedItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemIEField is the concrete ProtocolIEField[ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeUpdatedItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemIEField) WithoutReplay() ERABToBeUpdatedItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeUpdatedItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeUpdatedItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeUpdatedItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeUpdatedItemIEField{}
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
	var zero ERABToBeUpdatedItemIEValue

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

// ERABToBeSetupListCtxtSUReqValueCodec is the concrete ValueCodec[ERABToBeSetupListCtxtSUReq].
type ERABToBeSetupListCtxtSUReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupListCtxtSUReq,

		error)
	encode func(ERABToBeSetupListCtxtSUReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupListCtxtSUReq, aper.DecodeState,

	) (ERABToBeSetupListCtxtSUReq, aper.Snapshot,

	)
	compare func(ERABToBeSetupListCtxtSUReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupListCtxtSUReqValueCodec) New(value ERABToBeSetupListCtxtSUReq,

) (ERABToBeSetupListCtxtSUReqAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupListCtxtSUReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupListCtxtSUReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupListCtxtSUReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupListCtxtSUReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupListCtxtSUReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupListCtxtSUReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupListCtxtSUReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupListCtxtSUReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupListCtxtSUReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupListCtxtSUReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupListCtxtSUReqValueCodec) EncodeAPER(value ERABToBeSetupListCtxtSUReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupListCtxtSUReqValueCodec) encodeBudgetValue(value ERABToBeSetupListCtxtSUReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupListCtxtSUReqValueCodec) encodeChanged(value ERABToBeSetupListCtxtSUReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedListValueCodec is the concrete ValueCodec[ERABToBeUpdatedList].
type ERABToBeUpdatedListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedList,

		error)
	encode func(ERABToBeUpdatedList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedList, aper.DecodeState,

	) (ERABToBeUpdatedList, aper.Snapshot,

	)
	compare func(ERABToBeUpdatedList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedListValueCodec) New(value ERABToBeUpdatedList,

) (ERABToBeUpdatedListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedListValueCodec) EncodeAPER(value ERABToBeUpdatedListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedListValueCodec) encodeBudgetValue(value ERABToBeUpdatedList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedListValueCodec) encodeChanged(value ERABToBeUpdatedList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListValueCodec is the concrete ValueCodec[ERABInformationList].
type ERABInformationListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationList,

		error)
	encode func(ERABInformationList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationList, aper.DecodeState,

	) (ERABInformationList, aper.Snapshot,

	)
	compare func(ERABInformationList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListValueCodec) New(value ERABInformationList,

) (ERABInformationListAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListValueCodec) EncodeAPER(value ERABInformationListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListValueCodec) encodeBudgetValue(value ERABInformationList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListValueCodec) encodeChanged(value ERABInformationList,

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
func BridgeERABInformationListIEValueValidateS1APIEContainer(fields ERABInformationListIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// ERABInformationListIEContainer is the concrete ProtocolIEContainer[ERABInformationListIEValue].
type ERABInformationListIEContainer []ERABInformationListIEField

func BridgeERABInformationListItemExtIEsValueValidateS1APExtensionContainer(fields s28.ERABInformationListItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.ERABInformationListItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s28.ERABInformationListItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeERABInformationListItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueValidateS1APExtensionContainer(fields s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.ERABToBeSetupItemBearerSUReqExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s28.ERABToBeSetupItemBearerSUReqExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeERABToBeSetupItemBearerSUReqExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueValidateS1APExtensionContainer(fields s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.ERABToBeSetupItemCtxtSUReqExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s28.ERABToBeSetupItemCtxtSUReqExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeERABToBeSetupItemCtxtSUReqExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABToBeSetupItemBearerSUReqIEValueValidateS1APIEContainer(fields ERABToBeSetupItemBearerSUReqIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// ERABToBeSetupItemBearerSUReqIEContainer is the concrete ProtocolIEContainer[ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqIEContainer []ERABToBeSetupItemBearerSUReqIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABToBeSetupItemCtxtSUReqIEValueValidateS1APIEContainer(fields ERABToBeSetupItemCtxtSUReqIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// ERABToBeSetupItemCtxtSUReqIEContainer is the concrete ProtocolIEContainer[ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqIEContainer []ERABToBeSetupItemCtxtSUReqIEField

// ERABToBeSetupItemHOReqIEContainer is the concrete ProtocolIEContainer[ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqIEContainer []ERABToBeSetupItemHOReqIEField

// ERABToBeUpdatedItemIEContainer is the concrete ProtocolIEContainer[ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemIEContainer []ERABToBeUpdatedItemIEField

func ERABInformationListIEValueERABIEContainerListCodec(table s00.ERABInformationListIEValueIETable) ERABInformationListIEValueERABIEContainerListValueCodec {
	codec := ERABInformationListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABInformationListIEValueERABIEContainerListValueCodec{}
	}
	return ERABInformationListIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABInformationListIEValueERABIEContainerList(value), err
	}, encode: func(value ERABInformationListIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABInformationListIEContainer(value), fresh, budget)
	}, capture: func(v ERABInformationListIEValueERABIEContainerList, options aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABInformationListIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABInformationListIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABInformationListIEValueCompareS1APERABIEContainerList(&v, &s)
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
func ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListCodec(table s00.ERABToBeSetupItemBearerSUReqIEValueIETable) ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec {
	codec := ERABToBeSetupItemBearerSUReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec{}
	}
	return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList(value), err
	}, encode: func(value ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSetupItemBearerSUReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APERABIEContainerList(&v, &s)
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
func ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListCodec(table s00.ERABToBeSetupItemCtxtSUReqIEValueIETable) ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec {
	codec := ERABToBeSetupItemCtxtSUReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec{}
	}
	return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList(value), err
	}, encode: func(value ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSetupItemCtxtSUReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APERABIEContainerList(&v, &s)
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
func ERABInformationListItemExtIEsValueExtensionFieldTableCodec(table s00.ERABInformationListItemExtIEsValueExtensionTable) s28.ERABInformationListItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABInformationListItemExtIEsValueExtensionTableFieldBound(&table) {
		return s28.ERABInformationListItemExtIEsExtFieldValueCodec{}
	}
	return func() s28.ERABInformationListItemExtIEsExtFieldValueCodec {
		sealed := s28.ERABInformationListItemExtIEsExtFieldValueCodec{}
		*s28.BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ERABInformationListItemExtIEsExtField, error) {
			var field s28.ERABInformationListItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s28.BridgeERABInformationListItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s28.BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s28.ERABInformationListItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s28.BridgeERABInformationListItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s28.BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s28.ERABInformationListItemExtIEsExtField, options aper.DecodeState) (s28.ERABInformationListItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s28.BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s28.ERABInformationListItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSetupItemBearerSUReqExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTable) s28.ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableFieldBound(&table) {
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec{}
	}
	return func() s28.ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec {
		sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec{}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
			var field s28.ERABToBeSetupItemBearerSUReqExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, options aper.DecodeState) (s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTable) s28.ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTableFieldBound(&table) {
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec{}
	}
	return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec {
		sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec{}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
			var field s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, options aper.DecodeState) (s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSetupItemHOReqExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeSetupItemHOReqExtIEsValueExtensionTable) ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeSetupItemHOReqExtIEsValueExtensionTableFieldBound(&table) {
		return ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec{}
	}
	return ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtField, error) {
		var field ERABToBeSetupItemHOReqExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field ERABToBeSetupItemHOReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABToBeSetupItemHOReqExtIEsExtField, options aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemHOReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v ERABToBeSetupItemHOReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSetupItemHOReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func ERABInformationListItemExtIEsValueExtensionTableCodec(table s00.ERABInformationListItemExtIEsValueExtensionTable, bounds aper.ListBounds) s28.ERABInformationListItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABInformationListItemExtIEsValueExtensionTableFieldBound(&table) {
		return s28.ERABInformationListItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s28.ERABInformationListItemExtIEsExtContainerValueCodec {
		sealed := s28.ERABInformationListItemExtIEsExtContainerValueCodec{}
		*s28.BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ERABInformationListItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.ERABInformationListItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.ERABInformationListItemExtIEsExtField
					if err := s28.BridgeERABInformationListItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s28.BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s28.ERABInformationListItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s28.BridgeERABInformationListItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s28.BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s28.ERABInformationListItemExtIEsExtContainer, options aper.DecodeState) (s28.ERABInformationListItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s28.ERABInformationListItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableCodec(table s00.ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTable, bounds aper.ListBounds) s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableFieldBound(&table) {
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec {
		sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec{}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.ERABToBeSetupItemBearerSUReqExtIEsExtField
					if err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, options aper.DecodeState) (s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTableCodec(table s00.ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTable, bounds aper.ListBounds) s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTableFieldBound(&table) {
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec {
		sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec{}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField
					if err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, options aper.DecodeState) (s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSetupItemHOReqExtIEsValueExtensionTableCodec(table s00.ERABToBeSetupItemHOReqExtIEsValueExtensionTable, bounds aper.ListBounds) ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeSetupItemHOReqExtIEsValueExtensionTableFieldBound(&table) {
		return ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeSetupItemHOReqExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeSetupItemHOReqExtIEsExtField
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
		if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields ERABToBeSetupItemHOReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABToBeSetupItemHOReqExtIEsExtContainer, options aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemHOReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSetupItemHOReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeSetupItemHOReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func SecurityIndicationExtIEsValueExtensionTableCodec(table s00.SecurityIndicationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SecurityIndicationExtIEsExtContainerValueCodec {
	if !*s00.BridgeSecurityIndicationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecurityIndicationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SecurityIndicationExtIEsExtContainerValueCodec {
		sealed := s11.SecurityIndicationExtIEsExtContainerValueCodec{}
		*s11.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecurityIndicationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SecurityIndicationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SecurityIndicationExtIEsExtField
					if err := s11.BridgeSecurityIndicationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SecurityIndicationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSecurityIndicationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SecurityIndicationExtIEsExtContainer, options aper.DecodeState) (s11.SecurityIndicationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SecurityIndicationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s28.BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABInformationListIEValueIEFieldTableCodec(table s00.ERABInformationListIEValueIETable) ERABInformationListIEFieldValueCodec {
	if !*s00.BridgeERABInformationListIEValueIETableFieldBound(&table) {
		return ERABInformationListIEFieldValueCodec{}
	}
	return ERABInformationListIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEField, error) {
		var field ERABInformationListIEField
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
	}, encode: func(field ERABInformationListIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABInformationListIEField, options aper.DecodeState) (ERABInformationListIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABInformationListIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABInformationListIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABInformationListIEValueCompareS1APProtocolIEField(&v, &s)
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
func ERABToBeSetupItemBearerSUReqIEValueIEFieldTableCodec(table s00.ERABToBeSetupItemBearerSUReqIEValueIETable) ERABToBeSetupItemBearerSUReqIEFieldValueCodec {
	if !*s00.BridgeERABToBeSetupItemBearerSUReqIEValueIETableFieldBound(&table) {
		return ERABToBeSetupItemBearerSUReqIEFieldValueCodec{}
	}
	return ERABToBeSetupItemBearerSUReqIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEField, error) {
		var field ERABToBeSetupItemBearerSUReqIEField
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
	}, encode: func(field ERABToBeSetupItemBearerSUReqIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABToBeSetupItemBearerSUReqIEField, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABToBeSetupItemBearerSUReqIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEField(&v, &s)
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
func ERABToBeSetupItemCtxtSUReqIEValueIEFieldTableCodec(table s00.ERABToBeSetupItemCtxtSUReqIEValueIETable) ERABToBeSetupItemCtxtSUReqIEFieldValueCodec {
	if !*s00.BridgeERABToBeSetupItemCtxtSUReqIEValueIETableFieldBound(&table) {
		return ERABToBeSetupItemCtxtSUReqIEFieldValueCodec{}
	}
	return ERABToBeSetupItemCtxtSUReqIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEField, error) {
		var field ERABToBeSetupItemCtxtSUReqIEField
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
	}, encode: func(field ERABToBeSetupItemCtxtSUReqIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABToBeSetupItemCtxtSUReqIEField, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABToBeSetupItemCtxtSUReqIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEField(&v, &s)
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
func ERABInformationListIEValueIETableCodec(table s00.ERABInformationListIEValueIETable, bounds aper.ListBounds) ERABInformationListIEContainerValueCodec {
	if !*s00.BridgeERABInformationListIEValueIETableFieldBound(&table) {
		return ERABInformationListIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABInformationListIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABInformationListIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABInformationListIEField
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
		encode: func(fields ERABInformationListIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABInformationListIEContainer, options aper.DecodeState) (ERABInformationListIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABInformationListIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABInformationListIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABInformationListIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func ERABToBeSetupItemBearerSUReqIEValueIETableCodec(table s00.ERABToBeSetupItemBearerSUReqIEValueIETable, bounds aper.ListBounds) ERABToBeSetupItemBearerSUReqIEContainerValueCodec {
	if !*s00.BridgeERABToBeSetupItemBearerSUReqIEValueIETableFieldBound(&table) {
		return ERABToBeSetupItemBearerSUReqIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABToBeSetupItemBearerSUReqIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeSetupItemBearerSUReqIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeSetupItemBearerSUReqIEField
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
		encode: func(fields ERABToBeSetupItemBearerSUReqIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABToBeSetupItemBearerSUReqIEContainer, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSetupItemBearerSUReqIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func ERABToBeSetupItemCtxtSUReqIEValueIETableCodec(table s00.ERABToBeSetupItemCtxtSUReqIEValueIETable, bounds aper.ListBounds) ERABToBeSetupItemCtxtSUReqIEContainerValueCodec {
	if !*s00.BridgeERABToBeSetupItemCtxtSUReqIEValueIETableFieldBound(&table) {
		return ERABToBeSetupItemCtxtSUReqIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABToBeSetupItemCtxtSUReqIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeSetupItemCtxtSUReqIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeSetupItemCtxtSUReqIEField
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
		encode: func(fields ERABToBeSetupItemCtxtSUReqIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABToBeSetupItemCtxtSUReqIEContainer, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSetupItemCtxtSUReqIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func ERABInformationListIEValueProtocolErrorIEContainerListCodec(table s00.ERABInformationListIEValueIETable) ERABInformationListIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABInformationListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABInformationListIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABInformationListIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABInformationListIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABInformationListIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABInformationListIEContainer(value), fresh, budget)
	}, capture: func(v ERABInformationListIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABInformationListIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABInformationListIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABInformationListIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABInformationListIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeSetupItemBearerSUReqIEValueIETable) ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeSetupItemBearerSUReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSetupItemBearerSUReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListCodec(table s00.ERABToBeSetupItemCtxtSUReqIEValueIETable) ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABToBeSetupItemCtxtSUReqIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSetupItemCtxtSUReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func ERABInformationListIEValueProtocolIEContainerListCodec(table s00.ERABInformationListIEValueIETable, bounds aper.ListBounds) ERABInformationListIEValueProtocolIEContainerListValueCodec {
	codec := ERABInformationListIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABInformationListIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABInformationListIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABInformationListIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABInformationListIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABInformationListIEContainer(value), fresh, budget)
	}, capture: func(v ERABInformationListIEValueProtocolIEContainerList, options aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABInformationListIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABInformationListIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABInformationListIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListCodec(table s00.ERABToBeSetupItemBearerSUReqIEValueIETable, bounds aper.ListBounds) ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeSetupItemBearerSUReqIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSetupItemBearerSUReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListCodec(table s00.ERABToBeSetupItemCtxtSUReqIEValueIETable, bounds aper.ListBounds) ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec {
	codec := ERABToBeSetupItemCtxtSUReqIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABToBeSetupItemCtxtSUReqIEContainer(value), fresh, budget)
	}, capture: func(v ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// eRABInformationListIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABInformationListIEValue].
type ERABInformationListIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABInformationListIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABInformationListIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABInformationListIEValueCaptureS1APProtocolIEField(v *ERABInformationListIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABInformationListIEValueCompareS1APProtocolIEField(v *ERABInformationListIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABInformationListItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s28.ERABInformationListItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s28.ERABInformationListItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionField(v *s28.ERABInformationListItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s28.BridgeERABInformationListItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s28.BridgeERABInformationListItemExtIEsExtFieldFieldReplay(v), *s28.BridgeERABInformationListItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionField(v *s28.ERABInformationListItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s28.BridgeERABInformationListItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s28.BridgeERABInformationListItemExtIEsExtFieldFieldReplay(v), *s28.BridgeERABInformationListItemExtIEsExtFieldFieldWithoutReplay(v))
}

// eRABToBeSetupItemBearerSUReqExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s28.ERABToBeSetupItemBearerSUReqExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s28.ERABToBeSetupItemBearerSUReqExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionField(v *s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldReplay(v), *s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionField(v *s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldReplay(v), *s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldWithoutReplay(v))
}

// eRABToBeSetupItemCtxtSUReqExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s28.ERABToBeSetupItemCtxtSUReqExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCaptureS1APProtocolExtensionField(v *s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldReplay(v), *s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCompareS1APProtocolExtensionField(v *s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldReplay(v), *s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSetupItemHOReqExtIEsValueCaptureS1APProtocolExtensionField(v *ERABToBeSetupItemHOReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueCompareS1APProtocolExtensionField(v *ERABToBeSetupItemHOReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABToBeSetupItemBearerSUReqIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABToBeSetupItemBearerSUReqIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABToBeSetupItemBearerSUReqIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEField(v *ERABToBeSetupItemBearerSUReqIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEField(v *ERABToBeSetupItemBearerSUReqIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABToBeSetupItemCtxtSUReqIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABToBeSetupItemCtxtSUReqIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABToBeSetupItemCtxtSUReqIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEField(v *ERABToBeSetupItemCtxtSUReqIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEField(v *ERABToBeSetupItemCtxtSUReqIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// ERABInformationListItemAPERValue is the concrete APERValue[ERABInformationListItem].
type ERABInformationListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABInformationListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemAPERValue) WithoutReplay() ERABInformationListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityIndicationAPERValue is the concrete APERValue[SecurityIndication].
type SecurityIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s28.SecurityIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityIndicationAPERValue) WithoutReplay() SecurityIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupListBearerSUReqAPERValue is the concrete APERValue[ERABToBeSetupListBearerSUReq].
type ERABToBeSetupListBearerSUReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSetupListBearerSUReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupListBearerSUReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupListBearerSUReqAPERValue) WithoutReplay() ERABToBeSetupListBearerSUReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqAPERValue is the concrete APERValue[ERABToBeSetupItemBearerSUReq].
type ERABToBeSetupItemBearerSUReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSetupItemBearerSUReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqAPERValue is the concrete APERValue[ERABToBeSetupItemCtxtSUReq].
type ERABToBeSetupItemCtxtSUReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSetupItemCtxtSUReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqAPERValue is the concrete APERValue[ERABToBeSetupItemHOReq].
type ERABToBeSetupItemHOReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSetupItemHOReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqAPERValue) WithoutReplay() ERABToBeSetupItemHOReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemAPERValue is the concrete APERValue[ERABToBeUpdatedItem].
type ERABToBeUpdatedItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeUpdatedItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemAPERValue) WithoutReplay() ERABToBeUpdatedItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupListCtxtSUReqAPERValue is the concrete APERValue[ERABToBeSetupListCtxtSUReq].
type ERABToBeSetupListCtxtSUReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSetupListCtxtSUReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupListCtxtSUReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupListCtxtSUReqAPERValue) WithoutReplay() ERABToBeSetupListCtxtSUReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedListAPERValue is the concrete APERValue[ERABToBeUpdatedList].
type ERABToBeUpdatedListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeUpdatedList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedListAPERValue) WithoutReplay() ERABToBeUpdatedListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABInformationListAPERValue is the concrete APERValue[ERABInformationList].
type ERABInformationListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABInformationList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListAPERValue) WithoutReplay() ERABInformationListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABInformationListItemExtIEsValueValidateS1APIEContainer(fields s28.ERABInformationListItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s28.BridgeERABInformationListItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s28.BridgeERABInformationListItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s28.BridgeERABInformationListItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueValidateS1APIEContainer(fields s28.ERABToBeSetupItemBearerSUReqExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueValidateS1APIEContainer(fields s28.ERABToBeSetupItemCtxtSUReqExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodRule(field.Value).Assignment
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

// ERABToBeSetupItemHOReqExtIEsIEField is the concrete ProtocolIEField[ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemHOReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqExtIEsIEField) WithoutReplay() ERABToBeSetupItemHOReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemHOReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemHOReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemHOReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemHOReqExtIEsIEField{}
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
	var zero ERABToBeSetupItemHOReqExtIEsValue

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

// ERABToBeSetupItemHOReqExtIEsIEContainer is the concrete ProtocolIEContainer[ERABToBeSetupItemHOReqExtIEsValue].
type ERABToBeSetupItemHOReqExtIEsIEContainer []ERABToBeSetupItemHOReqExtIEsIEField

// ERABToBeSwitchedDLItemExtIEsIEField is the concrete ProtocolIEField[ERABToBeSwitchedDLItemExtIEsValue].
type ERABToBeSwitchedDLItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSwitchedDLItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemExtIEsIEField) WithoutReplay() ERABToBeSwitchedDLItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSwitchedDLItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSwitchedDLItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSwitchedDLItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedDLItemExtIEsIEField{}
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
	var zero ERABToBeSwitchedDLItemExtIEsValue

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

// ERABToBeSwitchedDLItemExtIEsIEContainer is the concrete ProtocolIEContainer[ERABToBeSwitchedDLItemExtIEsValue].
type ERABToBeSwitchedDLItemExtIEsIEContainer []ERABToBeSwitchedDLItemExtIEsIEField

// ERABInformationListIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABInformationListIEValue]].
type ERABInformationListIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, error)
	encode  func(ERABInformationListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListIEValueERABIEContainerList, aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABInformationListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListIEValueERABIEContainerListValueCodec) New(value ERABInformationListIEValueERABIEContainerList) (ERABInformationListIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABInformationListIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABInformationListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListIEValueERABIEContainerListValueCodec) encodeChanged(value ERABInformationListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABInformationListIEValue].
type ERABInformationListIEValueERABIEContainerList []ERABInformationListIEValueProtocolIESingleContainer

func BridgeERABInformationListIEValueCaptureS1APERABIEContainerList(v *ERABInformationListIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABInformationListIEValueCompareS1APERABIEContainerList(v *ERABInformationListIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, error)
	encode  func(ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) New(value ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList []ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer

func BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APERABIEContainerList(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APERABIEContainerList(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, error)
	encode  func(ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) New(value ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList []ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer

func BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APERABIEContainerList(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APERABIEContainerList(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueERABIEContainerList, error)
	encode  func(ERABToBeSetupItemHOReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemHOReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) New(value ERABToBeSetupItemHOReqIEValueERABIEContainerList) (ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemHOReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqIEValueERABIEContainerList []ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer

// ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEValueERABIEContainerList, error)
	encode  func(ERABToBeUpdatedItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItemIEValueERABIEContainerList, aper.DecodeState) (ERABToBeUpdatedItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeUpdatedItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) New(value ERABToBeUpdatedItemIEValueERABIEContainerList) (ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeUpdatedItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeUpdatedItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemIEValueERABIEContainerList []ERABToBeUpdatedItemIEValueProtocolIESingleContainer

// ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ERABToBeSetupItemHOReqExtIEsValue]].
type ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtField, error)
	encode  func(ERABToBeSetupItemHOReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeSetupItemHOReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) New(value ERABToBeSetupItemHOReqExtIEsExtField) (ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeSetupItemHOReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ERABToBeSwitchedDLItemExtIEsValue]].
type ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtField, error)
	encode  func(ERABToBeSwitchedDLItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItemExtIEsExtField, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeSwitchedDLItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) New(value ERABToBeSwitchedDLItemExtIEsExtField) (ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeSwitchedDLItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[ERABToBeSetupItemHOReqExtIEsValue]].
type ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtContainer, error)
	encode  func(ERABToBeSetupItemHOReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemHOReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) New(value ERABToBeSetupItemHOReqExtIEsExtContainer) (ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeSetupItemHOReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[ERABToBeSwitchedDLItemExtIEsValue]].
type ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtContainer, error)
	encode  func(ERABToBeSwitchedDLItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedDLItemExtIEsExtContainer, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeSwitchedDLItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) New(value ERABToBeSwitchedDLItemExtIEsExtContainer) (ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeSwitchedDLItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeSwitchedDLItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABInformationListIEValue]].
type ERABInformationListIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListIEField, error)
	encode  func(ERABInformationListIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListIEField, aper.DecodeState) (ERABInformationListIEField, aper.Snapshot)
	compare func(ERABInformationListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListIEFieldValueCodec) New(value ERABInformationListIEField) (ERABInformationListIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListIEFieldValueCodec) EncodeAPER(value ERABInformationListIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListIEFieldValueCodec) encodeBudgetValue(value ERABInformationListIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListIEFieldValueCodec) encodeChanged(value ERABInformationListIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEField, error)
	encode  func(ERABToBeSetupItemBearerSUReqIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqIEField, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEField, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqIEFieldValueCodec) New(value ERABToBeSetupItemBearerSUReqIEField) (ERABToBeSetupItemBearerSUReqIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqIEFieldValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqIEFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqIEFieldValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEField, error)
	encode  func(ERABToBeSetupItemCtxtSUReqIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqIEField, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEField, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) New(value ERABToBeSetupItemCtxtSUReqIEField) (ERABToBeSetupItemCtxtSUReqIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEField, error)
	encode  func(ERABToBeSetupItemHOReqIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReqIEField, aper.DecodeState) (ERABToBeSetupItemHOReqIEField, aper.Snapshot)
	compare func(ERABToBeSetupItemHOReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqIEFieldValueCodec) New(value ERABToBeSetupItemHOReqIEField) (ERABToBeSetupItemHOReqIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqIEFieldValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqIEFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReqIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqIEFieldValueCodec) encodeChanged(value ERABToBeSetupItemHOReqIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEField, error)
	encode  func(ERABToBeUpdatedItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItemIEField, aper.DecodeState) (ERABToBeUpdatedItemIEField, aper.Snapshot)
	compare func(ERABToBeUpdatedItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemIEFieldValueCodec) New(value ERABToBeUpdatedItemIEField) (ERABToBeUpdatedItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemIEFieldValueCodec) EncodeAPER(value ERABToBeUpdatedItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemIEFieldValueCodec) encodeBudgetValue(value ERABToBeUpdatedItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemIEFieldValueCodec) encodeChanged(value ERABToBeUpdatedItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABInformationListIEValue]].
type ERABInformationListIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListIEContainer, error)
	encode  func(ERABInformationListIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListIEContainer, aper.DecodeState) (ERABInformationListIEContainer, aper.Snapshot)
	compare func(ERABInformationListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListIEContainerValueCodec) New(value ERABInformationListIEContainer) (ERABInformationListIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListIEContainerValueCodec) EncodeAPER(value ERABInformationListIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListIEContainerValueCodec) encodeBudgetValue(value ERABInformationListIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListIEContainerValueCodec) encodeChanged(value ERABInformationListIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABInformationListIEValueCaptureS1APProtocolIEContainer(v *ERABInformationListIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABInformationListIEValueCompareS1APProtocolIEContainer(v *ERABInformationListIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemBearerSUReqIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEContainer, error)
	encode  func(ERABToBeSetupItemBearerSUReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqIEContainer, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqIEContainerValueCodec) New(value ERABToBeSetupItemBearerSUReqIEContainer) (ERABToBeSetupItemBearerSUReqIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqIEContainerValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqIEContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqIEContainerValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEContainer(v *ERABToBeSetupItemBearerSUReqIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEContainer(v *ERABToBeSetupItemBearerSUReqIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemCtxtSUReqIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEContainer, error)
	encode  func(ERABToBeSetupItemCtxtSUReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqIEContainer, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) New(value ERABToBeSetupItemCtxtSUReqIEContainer) (ERABToBeSetupItemCtxtSUReqIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEContainer(v *ERABToBeSetupItemCtxtSUReqIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEContainer(v *ERABToBeSetupItemCtxtSUReqIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemHOReqIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEContainer, error)
	encode  func(ERABToBeSetupItemHOReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReqIEContainer, aper.DecodeState) (ERABToBeSetupItemHOReqIEContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemHOReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqIEContainerValueCodec) New(value ERABToBeSetupItemHOReqIEContainer) (ERABToBeSetupItemHOReqIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqIEContainerValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqIEContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReqIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqIEContainerValueCodec) encodeChanged(value ERABToBeSetupItemHOReqIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEContainer, error)
	encode  func(ERABToBeUpdatedItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItemIEContainer, aper.DecodeState) (ERABToBeUpdatedItemIEContainer, aper.Snapshot)
	compare func(ERABToBeUpdatedItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemIEContainerValueCodec) New(value ERABToBeUpdatedItemIEContainer) (ERABToBeUpdatedItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemIEContainerValueCodec) EncodeAPER(value ERABToBeUpdatedItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemIEContainerValueCodec) encodeBudgetValue(value ERABToBeUpdatedItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemIEContainerValueCodec) encodeChanged(value ERABToBeUpdatedItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABInformationListIEValue]].
type ERABInformationListIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABInformationListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABInformationListIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABInformationListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) New(value ERABInformationListIEValueProtocolErrorIEContainerList) (ERABInformationListIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABInformationListIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABInformationListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABInformationListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABInformationListIEValue].
type ERABInformationListIEValueProtocolErrorIEContainerList []ERABInformationListIEValueProtocolIESingleContainer

func BridgeERABInformationListIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABInformationListIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABInformationListIEValueCompareS1APProtocolErrorIEContainerList(v *ERABInformationListIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList []ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer

func BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolErrorIEContainerList(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList []ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer

func BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolErrorIEContainerList(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList) (ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList []ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer

// ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList) (ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList []ERABToBeUpdatedItemIEValueProtocolIESingleContainer

// ERABInformationListIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABInformationListIEValue]].
type ERABInformationListIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, error)
	encode  func(ERABInformationListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListIEValueProtocolIEContainerList, aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABInformationListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListIEValueProtocolIEContainerListValueCodec) New(value ERABInformationListIEValueProtocolIEContainerList) (ERABInformationListIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABInformationListIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABInformationListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABInformationListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABInformationListIEValue].
type ERABInformationListIEValueProtocolIEContainerList []ERABInformationListIEValueProtocolIESingleContainer

func BridgeERABInformationListIEValueCaptureS1APProtocolIEContainerList(v *ERABInformationListIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABInformationListIEValueCompareS1APProtocolIEContainerList(v *ERABInformationListIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) New(value ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABToBeSetupItemBearerSUReqIEValue].
type ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList []ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer

func BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIEContainerList(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIEContainerList(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) New(value ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList []ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer

func BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIEContainerList(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIEContainerList(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) New(value ERABToBeSetupItemHOReqIEValueProtocolIEContainerList) (ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABToBeSetupItemHOReqIEValue].
type ERABToBeSetupItemHOReqIEValueProtocolIEContainerList []ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer

// ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeUpdatedItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeUpdatedItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) New(value ERABToBeUpdatedItemIEValueProtocolIEContainerList) (ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeUpdatedItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeUpdatedItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABToBeUpdatedItemIEValue].
type ERABToBeUpdatedItemIEValueProtocolIEContainerList []ERABToBeUpdatedItemIEValueProtocolIESingleContainer

// ERABInformationListIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABInformationListIEValue]].
type ERABInformationListIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListIEValueERABIEContainerListAPERValue) WithoutReplay() ERABInformationListIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemHOReqIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeUpdatedItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[ERABToBeSetupItemHOReqExtIEsValue]].
type ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemHOReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[ERABToBeSwitchedDLItemExtIEsValue]].
type ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedDLItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[ERABToBeSetupItemHOReqExtIEsValue]].
type ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemHOReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[ERABToBeSwitchedDLItemExtIEsValue]].
type ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedDLItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABInformationListIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABInformationListIEValue]].
type ERABInformationListIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListIEFieldAPERValue) WithoutReplay() ERABInformationListIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqIEFieldAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqIEFieldAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemHOReqIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqIEFieldAPERValue) WithoutReplay() ERABToBeSetupItemHOReqIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeUpdatedItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemIEFieldAPERValue) WithoutReplay() ERABToBeUpdatedItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABInformationListIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABInformationListIEValue]].
type ERABInformationListIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListIEContainerAPERValue) WithoutReplay() ERABInformationListIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqIEContainerAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqIEContainerAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemHOReqIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqIEContainerAPERValue) WithoutReplay() ERABToBeSetupItemHOReqIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeUpdatedItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemIEContainerAPERValue) WithoutReplay() ERABToBeUpdatedItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABInformationListIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABInformationListIEValue]].
type ERABInformationListIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABInformationListIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABInformationListIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABInformationListIEValue]].
type ERABInformationListIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABInformationListIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABToBeSetupItemBearerSUReqIEValue]].
type ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABToBeSetupItemCtxtSUReqIEValue]].
type ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABToBeSetupItemHOReqIEValue]].
type ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemHOReqIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABToBeUpdatedItemIEValue]].
type ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeUpdatedItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABInformationList(v *ERABInformationList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABInformationList(v *ERABInformationList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABInformationListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABInformationListIEValue(v *ERABInformationListIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(78):
			{
				f := s.Begin()
				s.Bool(v.rowERABInformationListItem == nil)
				if v.rowERABInformationListItem != nil {
					BridgeCaptureS1APERABInformationListItem(v.rowERABInformationListItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABInformationListIEValue) captureSemantics(s aper.SemanticCapture) ERABInformationListIEValue {
	BridgeCaptureS1APERABInformationListIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABInformationListIEValue(v *ERABInformationListIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(78):
			{
				f := s.Begin()
				s.Bool(v.rowERABInformationListItem == nil)
				if v.rowERABInformationListItem != nil {
					BridgeCompareS1APERABInformationListItem(v.rowERABInformationListItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABInformationListIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABInformationListIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABInformationListItem(v *ERABInformationListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	{
		f := s.Begin()
		s.Bool(v.DLForwarding == nil)
		if v.DLForwarding != nil {
			s00.BridgeCaptureS1APDLForwarding(v.DLForwarding, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABInformationListItem(v *ERABInformationListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	{
		f := s.Begin()
		s.Bool(v.DLForwarding == nil)
		if v.DLForwarding != nil {
			s02.BridgeCompareS1APDLForwarding(v.DLForwarding, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupItemBearerSUReq(v *ERABToBeSetupItemBearerSUReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s18.BridgeCaptureS1APERABLevelQoSParameters(&v.ERABlevelQoSParameters, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	s00.BridgeCaptureS1APNASPDU(&v.NASPDU, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSetupItemBearerSUReq(v *ERABToBeSetupItemBearerSUReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s18.BridgeCompareS1APERABLevelQoSParameters(&v.ERABlevelQoSParameters, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	s02.BridgeCompareS1APNASPDU(&v.NASPDU, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupItemBearerSUReqIEValue(v *ERABToBeSetupItemBearerSUReqIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(17):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupItemBearerSUReq == nil)
				if v.rowERABToBeSetupItemBearerSUReq != nil {
					BridgeCaptureS1APERABToBeSetupItemBearerSUReq(v.rowERABToBeSetupItemBearerSUReq, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemBearerSUReqIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemBearerSUReqIEValue {
	BridgeCaptureS1APERABToBeSetupItemBearerSUReqIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemBearerSUReqIEValue(v *ERABToBeSetupItemBearerSUReqIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(17):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupItemBearerSUReq == nil)
				if v.rowERABToBeSetupItemBearerSUReq != nil {
					BridgeCompareS1APERABToBeSetupItemBearerSUReq(v.rowERABToBeSetupItemBearerSUReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemBearerSUReqIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemBearerSUReqIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupItemCtxtSUReq(v *ERABToBeSetupItemCtxtSUReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s18.BridgeCaptureS1APERABLevelQoSParameters(&v.ERABlevelQoSParameters, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	{
		f := s.Begin()
		s.Bool(v.NASPDU == nil)
		if v.NASPDU != nil {
			s00.BridgeCaptureS1APNASPDU(v.NASPDU, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSetupItemCtxtSUReq(v *ERABToBeSetupItemCtxtSUReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s18.BridgeCompareS1APERABLevelQoSParameters(&v.ERABlevelQoSParameters, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	{
		f := s.Begin()
		s.Bool(v.NASPDU == nil)
		if v.NASPDU != nil {
			s02.BridgeCompareS1APNASPDU(v.NASPDU, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSetupItemCtxtSUReqExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupItemCtxtSUReqIEValue(v *ERABToBeSetupItemCtxtSUReqIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(52):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupItemCtxtSUReq == nil)
				if v.rowERABToBeSetupItemCtxtSUReq != nil {
					BridgeCaptureS1APERABToBeSetupItemCtxtSUReq(v.rowERABToBeSetupItemCtxtSUReq, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemCtxtSUReqIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemCtxtSUReqIEValue {
	BridgeCaptureS1APERABToBeSetupItemCtxtSUReqIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemCtxtSUReqIEValue(v *ERABToBeSetupItemCtxtSUReqIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(52):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupItemCtxtSUReq == nil)
				if v.rowERABToBeSetupItemCtxtSUReq != nil {
					BridgeCompareS1APERABToBeSetupItemCtxtSUReq(v.rowERABToBeSetupItemCtxtSUReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemCtxtSUReqIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemCtxtSUReqIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupItemHOReq(v *ERABToBeSetupItemHOReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	s18.BridgeCaptureS1APERABLevelQoSParameters(&v.ERABlevelQosParameters, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSetupItemHOReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSetupItemHOReq(v *ERABToBeSetupItemHOReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	s18.BridgeCompareS1APERABLevelQoSParameters(&v.ERABlevelQosParameters, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSetupItemHOReqExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupItemHOReqExtIEsValue(v *ERABToBeSetupItemHOReqExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(143):
			{
				f := s.Begin()
				s.Bool(v.rowDataForwardingNotPossible == nil)
				if v.rowDataForwardingNotPossible != nil {
					s00.BridgeCaptureS1APDataForwardingNotPossible(v.rowDataForwardingNotPossible, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(233):
			{
				f := s.Begin()
				s.Bool(v.rowBearerType == nil)
				if v.rowBearerType != nil {
					s00.BridgeCaptureS1APBearerType(v.rowBearerType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(305):
			{
				f := s.Begin()
				s.Bool(v.rowEthernetType == nil)
				if v.rowEthernetType != nil {
					s00.BridgeCaptureS1APEthernetType(v.rowEthernetType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					s28.BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemHOReqExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemHOReqExtIEsValue {
	BridgeCaptureS1APERABToBeSetupItemHOReqExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemHOReqExtIEsValue(v *ERABToBeSetupItemHOReqExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(143):
			{
				f := s.Begin()
				s.Bool(v.rowDataForwardingNotPossible == nil)
				if v.rowDataForwardingNotPossible != nil {
					s02.BridgeCompareS1APDataForwardingNotPossible(v.rowDataForwardingNotPossible, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(233):
			{
				f := s.Begin()
				s.Bool(v.rowBearerType == nil)
				if v.rowBearerType != nil {
					s02.BridgeCompareS1APBearerType(v.rowBearerType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(305):
			{
				f := s.Begin()
				s.Bool(v.rowEthernetType == nil)
				if v.rowEthernetType != nil {
					s02.BridgeCompareS1APEthernetType(v.rowEthernetType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					s28.BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemHOReqExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemHOReqExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupItemHOReqIEValue(v *ERABToBeSetupItemHOReqIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(27):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupItemHOReq == nil)
				if v.rowERABToBeSetupItemHOReq != nil {
					BridgeCaptureS1APERABToBeSetupItemHOReq(v.rowERABToBeSetupItemHOReq, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemHOReqIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemHOReqIEValue {
	BridgeCaptureS1APERABToBeSetupItemHOReqIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemHOReqIEValue(v *ERABToBeSetupItemHOReqIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(27):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupItemHOReq == nil)
				if v.rowERABToBeSetupItemHOReq != nil {
					BridgeCompareS1APERABToBeSetupItemHOReq(v.rowERABToBeSetupItemHOReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemHOReqIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemHOReqIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupListBearerSUReq(v *ERABToBeSetupListBearerSUReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeSetupListBearerSUReq(v *ERABToBeSetupListBearerSUReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemBearerSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABToBeSetupListCtxtSUReq(v *ERABToBeSetupListCtxtSUReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABToBeSetupListCtxtSUReq(v *ERABToBeSetupListCtxtSUReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABToBeSetupItemCtxtSUReqIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABToBeSwitchedDLItemExtIEsValue(v *ERABToBeSwitchedDLItemExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					s28.BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSwitchedDLItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeSwitchedDLItemExtIEsValue {
	BridgeCaptureS1APERABToBeSwitchedDLItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSwitchedDLItemExtIEsValue(v *ERABToBeSwitchedDLItemExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					s28.BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSwitchedDLItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSwitchedDLItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeUpdatedItem(v *ERABToBeUpdatedItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	{
		f := s.Begin()
		s.Bool(v.SecurityIndication == nil)
		if v.SecurityIndication != nil {
			s28.BridgeCaptureS1APSecurityIndication(v.SecurityIndication, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeUpdatedItem(v *ERABToBeUpdatedItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	{
		f := s.Begin()
		s.Bool(v.SecurityIndication == nil)
		if v.SecurityIndication != nil {
			s28.BridgeCompareS1APSecurityIndication(v.SecurityIndication, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeUpdatedItemIEValue(v *ERABToBeUpdatedItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(342):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeUpdatedItem == nil)
				if v.rowERABToBeUpdatedItem != nil {
					BridgeCaptureS1APERABToBeUpdatedItem(v.rowERABToBeUpdatedItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeUpdatedItemIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeUpdatedItemIEValue {
	BridgeCaptureS1APERABToBeUpdatedItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeUpdatedItemIEValue(v *ERABToBeUpdatedItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(342):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeUpdatedItem == nil)
				if v.rowERABToBeUpdatedItem != nil {
					BridgeCompareS1APERABToBeUpdatedItem(v.rowERABToBeUpdatedItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeUpdatedItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeUpdatedItemIEValue(&v, &s)
	return s
}

type ERABInformationList = []ERABInformationListIEValueProtocolIESingleContainer

// ERABInformationListItem represents the ASN.1 type E-RABInformationListItem (SEQUENCE).
type ERABInformationListItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                    `asn1:"tag:0,context,implicit"`
	DLForwarding      *s00.DLForwarding                             `asn1:"tag:1,context,implicit,optional" json:"DLForwarding,omitempty"`
	IEExtensions      s28.ERABInformationListItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type BridgeAsn1cAPERERABInformationListListValue struct{ Value ERABInformationList }

// MarshalAPER encodes ERABInformationListItem to APER format.
func (v *ERABInformationListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABInformationListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.DLForwarding != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if v.DLForwarding != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.DLForwarding), 1, true); err != nil {
			return fmt.Errorf("encoding dL-Forwarding: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s28.BridgeERABInformationListItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABInformationListItem from APER format.
func (v *ERABInformationListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABInformationListItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABInformationListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABInformationListItem")
	}
	bb.EnterComponent("ERABInformationListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABInformationListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABInformationListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABInformationListItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABInformationListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABInformationListItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_dlforwarding, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if opt_dlforwarding {
		val_dlforwarding, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DLForwarding"})
		if err != nil {
			return runtime.WrapDecodePath(err, "DLForwarding")
		}
		tmp_dlforwarding := s00.DLForwarding(val_dlforwarding)
		if err := aper.ChargeValue(bb, tmp_dlforwarding); err != nil {
			return err
		}
		v.DLForwarding = (*s00.DLForwarding)(bb.OwnInt64(int64(tmp_dlforwarding)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s28.ERABInformationListItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s28.ERABInformationListItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s28.BridgeERABInformationListItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ERABInformationListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABInformationListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABInformationListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABInformationListItem) WithoutReplay() ERABInformationListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABInformationListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABInformationListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABInformationListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABInformationListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABInformationListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABInformationListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABInformationListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABInformationListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABInformationListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABInformationListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABInformationListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABInformationListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABInformationListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABInformationListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABInformationListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABInformationListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABInformationListItem")
}
func (v *ERABInformationListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABInformationListItem")
}
func (v *ERABInformationListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABInformationListItem(v, &s)
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
func (v *ERABInformationListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABInformationListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABInformationListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABInformationListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABInformationListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABInformationListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABInformationListItem{}
		return report, aper.OperationError(err, "ERABInformationListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABInformationListItem")
}

// ERABToBeSetupItemHOReq represents the ASN.1 type E-RABToBeSetupItemHOReq (SEQUENCE).
type ERABToBeSetupItemHOReq struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	ERABID                 s00.ERABID                               `asn1:"tag:0,context,implicit"`
	TransportLayerAddress  s00.TransportLayerAddress                `asn1:"tag:1,context,implicit"`
	GTPTEID                s00.GTPTEID                              `asn1:"tag:2,context,implicit"`
	ERABlevelQosParameters s18.ERABLevelQoSParameters               `asn1:"tag:3,context,implicit"`
	IEExtensions           ERABToBeSetupItemHOReqExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                     `asn1:"-" json:"-"`
	extCount               int64                                    `asn1:"-" json:"-"`
	extPresent             []bool                                   `asn1:"-" json:"-"`
	extData                [][]byte                                 `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}
type ERABToBeUpdatedList = []ERABToBeUpdatedItemIEValueProtocolIESingleContainer

// ERABToBeUpdatedItem represents the ASN.1 type E-RABToBeUpdatedItem (SEQUENCE).
type ERABToBeUpdatedItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	ERABID             s00.ERABID                                `asn1:"tag:0,context,implicit"`
	SecurityIndication *s28.SecurityIndication                   `asn1:"tag:1,context,implicit,optional" json:"SecurityIndication,omitempty"`
	IEExtensions       s09.ERABToBeUpdatedItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                      `asn1:"-" json:"-"`
	extCount           int64                                     `asn1:"-" json:"-"`
	extPresent         []bool                                    `asn1:"-" json:"-"`
	extData            [][]byte                                  `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}
type ERABToBeSetupListBearerSUReq = []ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer

// ERABToBeSetupItemBearerSUReq represents the ASN.1 type E-RABToBeSetupItemBearerSUReq (SEQUENCE).
type ERABToBeSetupItemBearerSUReq struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	ERABID                 s00.ERABID                                         `asn1:"tag:0,context,implicit"`
	ERABlevelQoSParameters s18.ERABLevelQoSParameters                         `asn1:"tag:1,context,implicit"`
	TransportLayerAddress  s00.TransportLayerAddress                          `asn1:"tag:2,context,implicit"`
	GTPTEID                s00.GTPTEID                                        `asn1:"tag:3,context,implicit"`
	NASPDU                 s00.NASPDU                                         `asn1:"tag:4,context,implicit"`
	IEExtensions           s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                               `asn1:"-" json:"-"`
	extCount               int64                                              `asn1:"-" json:"-"`
	extPresent             []bool                                             `asn1:"-" json:"-"`
	extData                [][]byte                                           `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}
type ERABToBeSetupListCtxtSUReq = []ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer

// ERABToBeSetupItemCtxtSUReq represents the ASN.1 type E-RABToBeSetupItemCtxtSUReq (SEQUENCE).
type ERABToBeSetupItemCtxtSUReq struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	ERABID                 s00.ERABID                                       `asn1:"tag:0,context,implicit"`
	ERABlevelQoSParameters s18.ERABLevelQoSParameters                       `asn1:"tag:1,context,implicit"`
	TransportLayerAddress  s00.TransportLayerAddress                        `asn1:"tag:2,context,implicit"`
	GTPTEID                s00.GTPTEID                                      `asn1:"tag:3,context,implicit"`
	NASPDU                 *s00.NASPDU                                      `asn1:"tag:4,context,implicit,optional" json:"NASPDU,omitempty"`
	IEExtensions           s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                             `asn1:"-" json:"-"`
	extCount               int64                                            `asn1:"-" json:"-"`
	extPresent             []bool                                           `asn1:"-" json:"-"`
	extData                [][]byte                                         `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// MarshalAPER encodes ERABToBeSetupItemHOReq to APER format.
func (v *ERABToBeSetupItemHOReq) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeSetupItemHOReq) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeERABLevelQoSParametersMethodMarshalAPERTo(&v.ERABlevelQosParameters, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding e-RABlevelQosParameters: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeSetupItemHOReq from APER format.
func (v *ERABToBeSetupItemHOReq) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSetupItemHOReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSetupItemHOReq) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemHOReq")
	}
	bb.EnterComponent("ERABToBeSetupItemHOReq")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemHOReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSetupItemHOReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemHOReq")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABToBeSetupItemHOReq) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemHOReq{}
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
	toleranceMark_erablevelqosparameters := bb.EnterComponent("ERABlevelQosParameters")
	if err := s18.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&v.ERABlevelQosParameters, bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABlevelQosParameters")
	}
	bb.LeaveComponent(toleranceMark_erablevelqosparameters)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(ERABToBeSetupItemHOReqExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ERABToBeSetupItemHOReqExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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

type BridgeAsn1cAPERERABToBeUpdatedListListValue struct{ Value ERABToBeUpdatedList }

// MarshalAPER encodes ERABToBeUpdatedItem to APER format.
func (v *ERABToBeUpdatedItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeUpdatedItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.SecurityIndication != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if v.SecurityIndication != nil {
		if err := s28.BridgeSecurityIndicationMethodMarshalAPERTo(v.SecurityIndication, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding securityIndication: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeUpdatedItem from APER format.
func (v *ERABToBeUpdatedItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeUpdatedItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeUpdatedItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedItem")
	}
	bb.EnterComponent("ERABToBeUpdatedItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeUpdatedItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABToBeUpdatedItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeUpdatedItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_securityindication, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if opt_securityindication {
		toleranceMark_securityindication := bb.EnterComponent("SecurityIndication")
		var dec_securityindication s28.SecurityIndication
		if err := s28.BridgeSecurityIndicationMethodUnmarshalAPERFrom(&dec_securityindication, bb); err != nil {
			return runtime.WrapDecodePath(err, "SecurityIndication")
		}
		if err := aper.ChargeValue(bb, dec_securityindication); err != nil {
			return err
		}
		v.SecurityIndication = &dec_securityindication
		bb.LeaveComponent(toleranceMark_securityindication)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.ERABToBeUpdatedItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ERABToBeUpdatedItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABToBeSetupListBearerSUReqListValue struct{ Value ERABToBeSetupListBearerSUReq }

// MarshalAPER encodes ERABToBeSetupItemBearerSUReq to APER format.
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeERABLevelQoSParametersMethodMarshalAPERTo(&v.ERABlevelQoSParameters, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding e-RABlevelQoSParameters: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
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
				if err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeSetupItemBearerSUReq from APER format.
func (v *ERABToBeSetupItemBearerSUReq) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSetupItemBearerSUReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSetupItemBearerSUReq) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReq")
	}
	bb.EnterComponent("ERABToBeSetupItemBearerSUReq")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSetupItemBearerSUReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReq")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABToBeSetupItemBearerSUReq) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemBearerSUReq{}
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
	toleranceMark_erablevelqosparameters := bb.EnterComponent("ERABlevelQoSParameters")
	if err := s18.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&v.ERABlevelQoSParameters, bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABlevelQoSParameters")
	}
	bb.LeaveComponent(toleranceMark_erablevelqosparameters)
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
	val_naspdu, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NASPDU")
	}
	v.NASPDU = s00.NASPDU(val_naspdu)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s28.ERABToBeSetupItemBearerSUReqExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s28.ERABToBeSetupItemBearerSUReqExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABToBeSetupListCtxtSUReqListValue struct{ Value ERABToBeSetupListCtxtSUReq }

// MarshalAPER encodes ERABToBeSetupItemCtxtSUReq to APER format.
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.NASPDU != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := s18.BridgeERABLevelQoSParametersMethodMarshalAPERTo(&v.ERABlevelQoSParameters, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding e-RABlevelQoSParameters: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
	}
	if v.NASPDU != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.NASPDU), 0, 0, false); err != nil {
			return fmt.Errorf("encoding nAS-PDU: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeSetupItemCtxtSUReq from APER format.
func (v *ERABToBeSetupItemCtxtSUReq) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSetupItemCtxtSUReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSetupItemCtxtSUReq) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemCtxtSUReq")
	}
	bb.EnterComponent("ERABToBeSetupItemCtxtSUReq")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemCtxtSUReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSetupItemCtxtSUReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemCtxtSUReq")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABToBeSetupItemCtxtSUReq) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemCtxtSUReq{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_naspdu, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	toleranceMark_erablevelqosparameters := bb.EnterComponent("ERABlevelQoSParameters")
	if err := s18.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&v.ERABlevelQoSParameters, bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABlevelQoSParameters")
	}
	bb.LeaveComponent(toleranceMark_erablevelqosparameters)
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
	if opt_naspdu {
		val_naspdu, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "NASPDU")
		}
		tmp_naspdu := s00.NASPDU(val_naspdu)
		if err := aper.ChargeValue(bb, tmp_naspdu); err != nil {
			return err
		}
		v.NASPDU = &tmp_naspdu
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s28.ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ERABToBeSetupItemBearerSUReq) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSetupItemBearerSUReq", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSetupItemBearerSUReq", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSetupItemBearerSUReq) WithoutReplay() ERABToBeSetupItemBearerSUReq {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSetupItemBearerSUReq
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSetupItemCtxtSUReq) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSetupItemCtxtSUReq", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSetupItemCtxtSUReq", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSetupItemCtxtSUReq) WithoutReplay() ERABToBeSetupItemCtxtSUReq {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSetupItemCtxtSUReq
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSetupItemHOReq) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSetupItemHOReq", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSetupItemHOReq", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSetupItemHOReq) WithoutReplay() ERABToBeSetupItemHOReq {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSetupItemHOReq
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeUpdatedItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeUpdatedItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeUpdatedItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeUpdatedItem) WithoutReplay() ERABToBeUpdatedItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeUpdatedItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeSetupItemBearerSUReq) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeSetupItemBearerSUReq) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSetupItemBearerSUReq.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSetupItemBearerSUReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeSetupItemBearerSUReq) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSetupItemBearerSUReq.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSetupItemBearerSUReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeSetupItemCtxtSUReq) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeSetupItemCtxtSUReq) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSetupItemCtxtSUReq.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSetupItemCtxtSUReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeSetupItemCtxtSUReq) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSetupItemCtxtSUReq.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSetupItemCtxtSUReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeSetupItemHOReq) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeSetupItemHOReq) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSetupItemHOReq.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSetupItemHOReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeSetupItemHOReq) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSetupItemHOReq.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSetupItemHOReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeUpdatedItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeUpdatedItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeUpdatedItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeUpdatedItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeUpdatedItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeUpdatedItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeUpdatedItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeSetupItemBearerSUReq) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSetupItemBearerSUReq")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupItemBearerSUReq")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSetupItemBearerSUReq(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSetupItemBearerSUReq")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSetupItemBearerSUReq")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSetupItemBearerSUReq")
}
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSetupItemBearerSUReq")
}
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSetupItemBearerSUReq(v, &s)
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
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSetupItemBearerSUReq) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeSetupItemCtxtSUReq) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSetupItemCtxtSUReq")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupItemCtxtSUReq")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSetupItemCtxtSUReq(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSetupItemCtxtSUReq")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSetupItemCtxtSUReq")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSetupItemCtxtSUReq")
}
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSetupItemCtxtSUReq")
}
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSetupItemCtxtSUReq(v, &s)
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
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSetupItemCtxtSUReq) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeSetupItemHOReq) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSetupItemHOReq")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSetupItemHOReq) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupItemHOReq")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSetupItemHOReq(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSetupItemHOReq")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSetupItemHOReq")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSetupItemHOReq) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSetupItemHOReq")
}
func (v *ERABToBeSetupItemHOReq) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSetupItemHOReq")
}
func (v *ERABToBeSetupItemHOReq) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSetupItemHOReq(v, &s)
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
func (v *ERABToBeSetupItemHOReq) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSetupItemHOReq) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeUpdatedItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeUpdatedItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeUpdatedItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeUpdatedItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeUpdatedItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeUpdatedItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeUpdatedItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeUpdatedItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeUpdatedItem")
}
func (v *ERABToBeUpdatedItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeUpdatedItem")
}
func (v *ERABToBeUpdatedItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeUpdatedItem(v, &s)
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
func (v *ERABToBeUpdatedItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeUpdatedItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeSetupItemBearerSUReq) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupItemBearerSUReq")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSetupItemBearerSUReq
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSetupItemBearerSUReq(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSetupItemBearerSUReq{}
		return report, aper.OperationError(err, "ERABToBeSetupItemBearerSUReq")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSetupItemBearerSUReq")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeSetupItemCtxtSUReq) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupItemCtxtSUReq")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSetupItemCtxtSUReq
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSetupItemCtxtSUReq(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSetupItemCtxtSUReq{}
		return report, aper.OperationError(err, "ERABToBeSetupItemCtxtSUReq")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSetupItemCtxtSUReq")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeSetupItemHOReq) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupItemHOReq")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSetupItemHOReq
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSetupItemHOReq(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSetupItemHOReq{}
		return report, aper.OperationError(err, "ERABToBeSetupItemHOReq")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSetupItemHOReq")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeUpdatedItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeUpdatedItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeUpdatedItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeUpdatedItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeUpdatedItem{}
		return report, aper.OperationError(err, "ERABToBeUpdatedItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeUpdatedItem")
}

type ERABInformationListIEValue struct {
	id                         s00.ProtocolIEID
	received                   aper.WireSpan
	replay                     aper.Snapshot
	opaque                     aper.OpaqueOpenType
	isOpaque                   bool
	rowERABInformationListItem *ERABInformationListItem
}

func (v ERABInformationListIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(78):
		return v.rowERABInformationListItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABInformationListIEValue and reports whether the opaque alternative is selected.
func (v *ERABInformationListIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABInformationListIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListIEs"}}
}
func (ERABInformationListIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(78):
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

// AsERABInformationListItem returns the selected ERABInformationListItem value of ERABInformationListIEValue and reports whether that alternative is active.
func (v *ERABInformationListIEValue) AsERABInformationListItem() (*ERABInformationListItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(78) || v.rowERABInformationListItem == nil {
		return nil, false
	}
	return v.rowERABInformationListItem, true
}
func (v ERABInformationListIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABInformationListIEValue, error) {
	out := ERABInformationListIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(78):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABInformationListItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABInformationListItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABInformationListItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABInformationListItem = &value
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
func (v ERABInformationListIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABInformationListIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(78):
		if v.rowERABInformationListItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListIEs.id-E-RABInformationListItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABInformationListItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABInformationListIEValue:", v.id)
	}
}

type ERABToBeSetupItemBearerSUReqIEValue struct {
	id                              s00.ProtocolIEID
	received                        aper.WireSpan
	replay                          aper.Snapshot
	opaque                          aper.OpaqueOpenType
	isOpaque                        bool
	rowERABToBeSetupItemBearerSUReq *ERABToBeSetupItemBearerSUReq
}

func (v ERABToBeSetupItemBearerSUReqIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(17):
		return v.rowERABToBeSetupItemBearerSUReq != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSetupItemBearerSUReqIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSetupItemBearerSUReqIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemBearerSUReqIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqIEs"}}
}
func (ERABToBeSetupItemBearerSUReqIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(17):
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

// AsERABToBeSetupItemBearerSUReq returns the selected ERABToBeSetupItemBearerSUReq value of ERABToBeSetupItemBearerSUReqIEValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemBearerSUReqIEValue) AsERABToBeSetupItemBearerSUReq() (*ERABToBeSetupItemBearerSUReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(17) || v.rowERABToBeSetupItemBearerSUReq == nil {
		return nil, false
	}
	return v.rowERABToBeSetupItemBearerSUReq, true
}
func (v ERABToBeSetupItemBearerSUReqIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemBearerSUReqIEValue, error) {
	out := ERABToBeSetupItemBearerSUReqIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(17):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeSetupItemBearerSUReq
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSetupItemBearerSUReq:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeSetupItemBearerSUReq")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeSetupItemBearerSUReq = &value
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
func (v ERABToBeSetupItemBearerSUReqIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSetupItemBearerSUReqIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(17):
		if v.rowERABToBeSetupItemBearerSUReq == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqIEs.id-E-RABToBeSetupItemBearerSUReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeSetupItemBearerSUReq.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemBearerSUReqIEValue:", v.id)
	}
}

type ERABToBeSetupItemCtxtSUReqIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowERABToBeSetupItemCtxtSUReq *ERABToBeSetupItemCtxtSUReq
}

func (v ERABToBeSetupItemCtxtSUReqIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(52):
		return v.rowERABToBeSetupItemCtxtSUReq != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSetupItemCtxtSUReqIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSetupItemCtxtSUReqIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemCtxtSUReqIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqIEs"}}
}
func (ERABToBeSetupItemCtxtSUReqIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(52):
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

// AsERABToBeSetupItemCtxtSUReq returns the selected ERABToBeSetupItemCtxtSUReq value of ERABToBeSetupItemCtxtSUReqIEValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemCtxtSUReqIEValue) AsERABToBeSetupItemCtxtSUReq() (*ERABToBeSetupItemCtxtSUReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(52) || v.rowERABToBeSetupItemCtxtSUReq == nil {
		return nil, false
	}
	return v.rowERABToBeSetupItemCtxtSUReq, true
}
func (v ERABToBeSetupItemCtxtSUReqIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemCtxtSUReqIEValue, error) {
	out := ERABToBeSetupItemCtxtSUReqIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(52):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeSetupItemCtxtSUReq
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSetupItemCtxtSUReq:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeSetupItemCtxtSUReq")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeSetupItemCtxtSUReq = &value
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
func (v ERABToBeSetupItemCtxtSUReqIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSetupItemCtxtSUReqIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(52):
		if v.rowERABToBeSetupItemCtxtSUReq == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqIEs.id-E-RABToBeSetupItemCtxtSUReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeSetupItemCtxtSUReq.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemCtxtSUReqIEValue:", v.id)
	}
}

type ERABToBeSetupItemHOReqExtIEsValue struct {
	id                           s00.ProtocolIEID
	received                     aper.WireSpan
	replay                       aper.Snapshot
	opaque                       aper.OpaqueOpenType
	isOpaque                     bool
	rowDataForwardingNotPossible *s00.DataForwardingNotPossible
	rowBearerType                *s00.BearerType
	rowEthernetType              *s00.EthernetType
	rowSecurityIndication        *s28.SecurityIndication
}

func (v ERABToBeSetupItemHOReqExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(143):
		return v.rowDataForwardingNotPossible != nil
	case s00.ProtocolIEID(233):
		return v.rowBearerType != nil
	case s00.ProtocolIEID(305):
		return v.rowEthernetType != nil
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSetupItemHOReqExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSetupItemHOReqExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemHOReqExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemHOReq-ExtIEs"}}
}
func (ERABToBeSetupItemHOReqExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(143):
		return aper.UnknownSelector
	case s00.ProtocolIEID(233):
		return aper.UnknownSelector
	case s00.ProtocolIEID(305):
		return aper.UnknownSelector
	case s00.ProtocolIEID(332):
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

// AsDataForwardingNotPossible returns the selected DataForwardingNotPossible value of ERABToBeSetupItemHOReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemHOReqExtIEsValue) AsDataForwardingNotPossible() (*s00.DataForwardingNotPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(143) || v.rowDataForwardingNotPossible == nil {
		return nil, false
	}
	return v.rowDataForwardingNotPossible, true
}

// AsBearerType returns the selected BearerType value of ERABToBeSetupItemHOReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemHOReqExtIEsValue) AsBearerType() (*s00.BearerType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(233) || v.rowBearerType == nil {
		return nil, false
	}
	return v.rowBearerType, true
}

// AsEthernetType returns the selected EthernetType value of ERABToBeSetupItemHOReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemHOReqExtIEsValue) AsEthernetType() (*s00.EthernetType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(305) || v.rowEthernetType == nil {
		return nil, false
	}
	return v.rowEthernetType, true
}

// AsSecurityIndication returns the selected SecurityIndication value of ERABToBeSetupItemHOReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemHOReqExtIEsValue) AsSecurityIndication() (*s28.SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}
func (v ERABToBeSetupItemHOReqExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemHOReqExtIEsValue, error) {
	out := ERABToBeSetupItemHOReqExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(143):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DataForwardingNotPossible"})
		value := s00.DataForwardingNotPossible(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DataForwardingNotPossible:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDataForwardingNotPossible = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(233):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BearerType"})
		value := s00.BearerType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "BearerType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowBearerType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(305):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EthernetType"})
		value := s00.EthernetType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EthernetType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEthernetType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(332):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.SecurityIndication
		child := scope
		if err := s28.BridgeSecurityIndicationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		*s28.BridgeSecurityIndicationFieldPerPadding(&value) = padding
		*s28.BridgeSecurityIndicationFieldReceived(&value) = true
		raw.RetainContents(s28.BridgeSecurityIndicationFieldReceivedBytes(&value))
		*s28.BridgeSecurityIndicationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSecurityIndication = &value
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
func (v ERABToBeSetupItemHOReqExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSetupItemHOReqExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(143):
		if v.rowDataForwardingNotPossible == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemHOReq-ExtIEs.id-Data-Forwarding-Not-Possible:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowDataForwardingNotPossible), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(233):
		if v.rowBearerType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemHOReq-ExtIEs.id-BearerType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowBearerType), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(305):
		if v.rowEthernetType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemHOReq-ExtIEs.id-Ethernet-Type:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEthernetType), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(332):
		if v.rowSecurityIndication == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemHOReq-ExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeSecurityIndicationMethodMarshalAPERBudget(v.rowSecurityIndication, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemHOReqExtIEsValue:", v.id)
	}
}

type ERABToBeSetupItemHOReqIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowERABToBeSetupItemHOReq *ERABToBeSetupItemHOReq
}

func (v ERABToBeSetupItemHOReqIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(27):
		return v.rowERABToBeSetupItemHOReq != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSetupItemHOReqIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSetupItemHOReqIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemHOReqIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemHOReqIEs"}}
}
func (ERABToBeSetupItemHOReqIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(27):
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

// AsERABToBeSetupItemHOReq returns the selected ERABToBeSetupItemHOReq value of ERABToBeSetupItemHOReqIEValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemHOReqIEValue) AsERABToBeSetupItemHOReq() (*ERABToBeSetupItemHOReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(27) || v.rowERABToBeSetupItemHOReq == nil {
		return nil, false
	}
	return v.rowERABToBeSetupItemHOReq, true
}
func (v ERABToBeSetupItemHOReqIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemHOReqIEValue, error) {
	out := ERABToBeSetupItemHOReqIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(27):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeSetupItemHOReq
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSetupItemHOReq:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeSetupItemHOReq")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeSetupItemHOReq = &value
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
func (v ERABToBeSetupItemHOReqIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABToBeSetupItemHOReqIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(27):
		if v.rowERABToBeSetupItemHOReq == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemHOReqIEs.id-E-RABToBeSetupItemHOReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeSetupItemHOReq.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemHOReqIEValue:", v.id)
	}
}

type ERABToBeSwitchedDLItemExtIEsValue struct {
	id                    s00.ProtocolIEID
	received              aper.WireSpan
	replay                aper.Snapshot
	opaque                aper.OpaqueOpenType
	isOpaque              bool
	rowSecurityIndication *s28.SecurityIndication
}

func (v ERABToBeSwitchedDLItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSwitchedDLItemExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSwitchedDLItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSwitchedDLItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLItem-ExtIEs"}}
}
func (ERABToBeSwitchedDLItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(332):
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

// AsSecurityIndication returns the selected SecurityIndication value of ERABToBeSwitchedDLItemExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSwitchedDLItemExtIEsValue) AsSecurityIndication() (*s28.SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}
func (v ERABToBeSwitchedDLItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSwitchedDLItemExtIEsValue, error) {
	out := ERABToBeSwitchedDLItemExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(332):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.SecurityIndication
		child := scope
		if err := s28.BridgeSecurityIndicationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		*s28.BridgeSecurityIndicationFieldPerPadding(&value) = padding
		*s28.BridgeSecurityIndicationFieldReceived(&value) = true
		raw.RetainContents(s28.BridgeSecurityIndicationFieldReceivedBytes(&value))
		*s28.BridgeSecurityIndicationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSecurityIndication = &value
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
func (v ERABToBeSwitchedDLItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSwitchedDLItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(332):
		if v.rowSecurityIndication == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSwitchedDLItem-ExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeSecurityIndicationMethodMarshalAPERBudget(v.rowSecurityIndication, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSwitchedDLItemExtIEsValue:", v.id)
	}
}

type ERABToBeUpdatedItemIEValue struct {
	id                     s00.ProtocolIEID
	received               aper.WireSpan
	replay                 aper.Snapshot
	opaque                 aper.OpaqueOpenType
	isOpaque               bool
	rowERABToBeUpdatedItem *ERABToBeUpdatedItem
}

func (v ERABToBeUpdatedItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(342):
		return v.rowERABToBeUpdatedItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeUpdatedItemIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeUpdatedItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeUpdatedItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedItemIEs"}}
}
func (ERABToBeUpdatedItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(342):
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

// AsERABToBeUpdatedItem returns the selected ERABToBeUpdatedItem value of ERABToBeUpdatedItemIEValue and reports whether that alternative is active.
func (v *ERABToBeUpdatedItemIEValue) AsERABToBeUpdatedItem() (*ERABToBeUpdatedItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(342) || v.rowERABToBeUpdatedItem == nil {
		return nil, false
	}
	return v.rowERABToBeUpdatedItem, true
}
func (v ERABToBeUpdatedItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeUpdatedItemIEValue, error) {
	out := ERABToBeUpdatedItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(342):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeUpdatedItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeUpdatedItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeUpdatedItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeUpdatedItem = &value
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
func (v ERABToBeUpdatedItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABToBeUpdatedItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(342):
		if v.rowERABToBeUpdatedItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeUpdatedItemIEs.id-E-RABToBeUpdatedItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeUpdatedItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeUpdatedItemIEValue:", v.id)
	}
}

type ERABInformationListIETable struct{}

func ERABInformationListIEs() ERABInformationListIETable { return ERABInformationListIETable{} }

// ID returns the ASN.1 object-set identity of ERABInformationListIETable.
func (ERABInformationListIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABInformationListIETable.
func (ERABInformationListIETable) Table() s00.ERABInformationListIEValueIETable {
	return func() s00.ERABInformationListIEValueIETable {
		sealed := s00.ERABInformationListIEValueIETable{}
		*s00.BridgeERABInformationListIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABInformationListIETable) infoERABInformationListItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABInformationListIEs().ID(), ID: s00.ProtocolIEID(78), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListIEs", Row: "id-E-RABInformationListItem"}}}
}

// ERABInformationListItem returns the typed binding for the ERABInformationListItem row of ERABInformationListIETable.
func (t ERABInformationListIETable) ERABInformationListItem() ERABInformationListERABInformationListItemIEBinding {
	return ERABInformationListERABInformationListItemIEBinding{info: t.infoERABInformationListItem(), codec: ERABInformationListItemValueCodec{path: "ERABInformationListItem",
		decode: func(data []byte, options aper.DecodeState) (ERABInformationListItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABInformationListItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABInformationListItem")
			var zero ERABInformationListIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(78), raw)
			if err != nil {
				var empty ERABInformationListItem
				return empty, err
			}
			value, ok := decoded.AsERABInformationListItem()
			if !ok {
				var empty ERABInformationListItem
				return empty, fmt.Errorf("binding E-RABInformationListIEs.id-E-RABInformationListItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABInformationListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABInformationListIEValue{id: s00.ProtocolIEID(78), rowERABInformationListItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABInformationListItem, options aper.DecodeState) (ERABInformationListItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABInformationListItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v ERABInformationListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABInformationListItem(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABInformationListItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABInformationListItem) ERABInformationListIEValue {
		return ERABInformationListIEValue{id: s00.ProtocolIEID(78), rowERABInformationListItem: &value}
	}, get: func(value *ERABInformationListIEValue) (*ERABInformationListItem, bool) {
		return value.AsERABInformationListItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABInformationListIETable.
func (t ERABInformationListIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABInformationListIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABInformationListIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(78):
		return ERABInformationListIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABInformationListItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABInformationListIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABInformationListIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABInformationListIEField{Id: id, Criticality: criticality, Value: ERABInformationListIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABInformationListItemExtIETable struct{}

func ERABInformationListItemExtIEs() ERABInformationListItemExtIETable {
	return ERABInformationListItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABInformationListItemExtIETable.
func (ERABInformationListItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABInformationListItemExtIETable.
func (ERABInformationListItemExtIETable) Table() s00.ERABInformationListItemExtIEsValueExtensionTable {
	return func() s00.ERABInformationListItemExtIEsValueExtensionTable {
		sealed := s00.ERABInformationListItemExtIEsValueExtensionTable{}
		*s00.BridgeERABInformationListItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABInformationListItemExtIETable) infoDAPSRequestInfo() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABInformationListItemExtIEs().ID(), ID: s00.ProtocolExtensionID(317), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSRequestInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs", Row: "id-DAPSRequestInfo"}}}
}

// DAPSRequestInfo returns the typed binding for the DAPSRequestInfo row of ERABInformationListItemExtIETable.
func (t ERABInformationListItemExtIETable) DAPSRequestInfo() s28.ERABInformationListItemExtIEsDAPSRequestInfoExtBinding {
	return func() s28.ERABInformationListItemExtIEsDAPSRequestInfoExtBinding {
		sealed := s28.ERABInformationListItemExtIEsDAPSRequestInfoExtBinding{}
		*s28.BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldInfo(&sealed) = t.infoDAPSRequestInfo()
		*s28.BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldCodec(&sealed) = func() s14.DAPSRequestInfoValueCodec {
			sealed := s14.DAPSRequestInfoValueCodec{}
			*s14.BridgeDAPSRequestInfoValueCodecFieldPath(&sealed) = "DAPSRequestInfo"
			*s14.BridgeDAPSRequestInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.DAPSRequestInfo, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s14.DAPSRequestInfo
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("DAPSRequestInfo")
				var zero s28.ERABInformationListItemExtIEsValue
				decoded, err := s28.BridgeERABInformationListItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(317), raw)
				if err != nil {
					var empty s14.DAPSRequestInfo
					return empty, err
				}
				value, ok := decoded.AsDAPSRequestInfo()
				if !ok {
					var empty s14.DAPSRequestInfo
					return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-DAPSRequestInfo: no selected value")
				}
				return *value, nil
			}
			*s14.BridgeDAPSRequestInfoValueCodecFieldEncode(&sealed) = func(value s14.DAPSRequestInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABInformationListItemExtIEsValueMethodEncodeFresh((func() s28.ERABInformationListItemExtIEsValue {
					sealed := s28.ERABInformationListItemExtIEsValue{}
					*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(317)
					*s28.BridgeERABInformationListItemExtIEsValueFieldRowDAPSRequestInfo(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s14.BridgeDAPSRequestInfoValueCodecFieldCapture(&sealed) = func(v s14.DAPSRequestInfo, options aper.DecodeState) (s14.DAPSRequestInfo, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s14.BridgeCaptureS1APDAPSRequestInfo(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s14.BridgeDAPSRequestInfoValueCodecFieldCompare(&sealed) = func(v s14.DAPSRequestInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s14.BridgeCompareS1APDAPSRequestInfo(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s14.BridgeDAPSRequestInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DAPSRequestInfo"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldInject(&sealed) = func(value s14.DAPSRequestInfo) s28.ERABInformationListItemExtIEsValue {
			return func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(317)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowDAPSRequestInfo(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldGet(&sealed) = func(value *s28.ERABInformationListItemExtIEsValue) (*s14.DAPSRequestInfo, bool) {
			return value.AsDAPSRequestInfo()
		}
		return sealed
	}()
}
func (ERABInformationListItemExtIETable) infoSourceTransportLayerAddress() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABInformationListItemExtIEs().ID(), ID: s00.ProtocolExtensionID(328), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs", Row: "id-SourceTransportLayerAddress"}}}
}

// SourceTransportLayerAddress returns the typed binding for the SourceTransportLayerAddress row of ERABInformationListItemExtIETable.
func (t ERABInformationListItemExtIETable) SourceTransportLayerAddress() s28.ERABInformationListItemExtIEsTransportLayerAddressExtBinding {
	return func() s28.ERABInformationListItemExtIEsTransportLayerAddressExtBinding {
		sealed := s28.ERABInformationListItemExtIEsTransportLayerAddressExtBinding{}
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldInfo(&sealed) = t.infoSourceTransportLayerAddress()
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldCodec(&sealed) = func() s02.TransportLayerAddressValueCodec {
			sealed := s02.TransportLayerAddressValueCodec{}
			*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
			*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
				var zero s28.ERABInformationListItemExtIEsValue
				decoded, err := s28.BridgeERABInformationListItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(328), raw)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, err
				}
				value, ok := decoded.AsSourceTransportLayerAddress()
				if !ok {
					var empty s00.TransportLayerAddress
					return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-SourceTransportLayerAddress: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABInformationListItemExtIEsValueMethodEncodeFresh((func() s28.ERABInformationListItemExtIEsValue {
					sealed := s28.ERABInformationListItemExtIEsValue{}
					*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(328)
					*s28.BridgeERABInformationListItemExtIEsValueFieldRowSourceTransportLayerAddress(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldCapture(&sealed) = func(v s00.TransportLayerAddress, options aper.DecodeState) (s00.TransportLayerAddress, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTransportLayerAddress(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)

				return v, root
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldCompare(&sealed) = func(v s00.TransportLayerAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APTransportLayerAddress(&v, &s)
				s.End(f, root, false)

				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportLayerAddress"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldInject(&sealed) = func(value s00.TransportLayerAddress) s28.ERABInformationListItemExtIEsValue {
			return func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(328)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowSourceTransportLayerAddress(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldGet(&sealed) = func(value *s28.ERABInformationListItemExtIEsValue) (*s00.TransportLayerAddress, bool) {
			return value.AsSourceTransportLayerAddress()
		}
		return sealed
	}()
}
func (ERABInformationListItemExtIETable) infoSecurityIndication() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABInformationListItemExtIEs().ID(), ID: s00.ProtocolExtensionID(332), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs", Row: "id-SecurityIndication"}}}
}

// SecurityIndication returns the typed binding for the SecurityIndication row of ERABInformationListItemExtIETable.
func (t ERABInformationListItemExtIETable) SecurityIndication() ERABInformationListItemExtIEsSecurityIndicationExtBinding {
	return ERABInformationListItemExtIEsSecurityIndicationExtBinding{info: t.infoSecurityIndication(), codec: SecurityIndicationValueCodec{path: "SecurityIndication",
		decode: func(data []byte, options aper.DecodeState) (s28.SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero s28.ERABInformationListItemExtIEsValue
			decoded, err := s28.BridgeERABInformationListItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty s28.SecurityIndication
				return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value s28.SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s28.BridgeERABInformationListItemExtIEsValueMethodEncodeFresh((func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowSecurityIndication(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s28.SecurityIndication, options aper.DecodeState) (s28.SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v s28.SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s28.SecurityIndication) s28.ERABInformationListItemExtIEsValue {
		return func() s28.ERABInformationListItemExtIEsValue {
			sealed := s28.ERABInformationListItemExtIEsValue{}
			*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
			*s28.BridgeERABInformationListItemExtIEsValueFieldRowSecurityIndication(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s28.ERABInformationListItemExtIEsValue) (*s28.SecurityIndication, bool) {
		return value.AsSecurityIndication()
	}}
}
func (ERABInformationListItemExtIETable) infoSourceNodeTransportLayerAddress() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABInformationListItemExtIEs().ID(), ID: s00.ProtocolExtensionID(340), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs", Row: "id-SourceNodeTransportLayerAddress"}}}
}

// SourceNodeTransportLayerAddress returns the typed binding for the SourceNodeTransportLayerAddress row of ERABInformationListItemExtIETable.
func (t ERABInformationListItemExtIETable) SourceNodeTransportLayerAddress() s28.ERABInformationListItemExtIEsTransportLayerAddressExtBinding {
	return func() s28.ERABInformationListItemExtIEsTransportLayerAddressExtBinding {
		sealed := s28.ERABInformationListItemExtIEsTransportLayerAddressExtBinding{}
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldInfo(&sealed) = t.infoSourceNodeTransportLayerAddress()
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldCodec(&sealed) = func() s02.TransportLayerAddressValueCodec {
			sealed := s02.TransportLayerAddressValueCodec{}
			*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
			*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
				var zero s28.ERABInformationListItemExtIEsValue
				decoded, err := s28.BridgeERABInformationListItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(340), raw)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, err
				}
				value, ok := decoded.AsSourceNodeTransportLayerAddress()
				if !ok {
					var empty s00.TransportLayerAddress
					return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-SourceNodeTransportLayerAddress: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABInformationListItemExtIEsValueMethodEncodeFresh((func() s28.ERABInformationListItemExtIEsValue {
					sealed := s28.ERABInformationListItemExtIEsValue{}
					*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(340)
					*s28.BridgeERABInformationListItemExtIEsValueFieldRowSourceNodeTransportLayerAddress(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldCapture(&sealed) = func(v s00.TransportLayerAddress, options aper.DecodeState) (s00.TransportLayerAddress, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTransportLayerAddress(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)

				return v, root
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldCompare(&sealed) = func(v s00.TransportLayerAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APTransportLayerAddress(&v, &s)
				s.End(f, root, false)

				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportLayerAddress"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldInject(&sealed) = func(value s00.TransportLayerAddress) s28.ERABInformationListItemExtIEsValue {
			return func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(340)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowSourceNodeTransportLayerAddress(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldGet(&sealed) = func(value *s28.ERABInformationListItemExtIEsValue) (*s00.TransportLayerAddress, bool) {
			return value.AsSourceNodeTransportLayerAddress()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABInformationListItemExtIETable.
func (t ERABInformationListItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (s28.ERABInformationListItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(317):
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DAPSRequestInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(328):
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SourceTransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(332):
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(340):
		return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SourceNodeTransportLayerAddress requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s28.ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return s28.ERABInformationListItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s28.ERABInformationListItemExtIEsValue {
			sealed := s28.ERABInformationListItemExtIEsValue{}
			*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = id
			*s28.BridgeERABInformationListItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s28.BridgeERABInformationListItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSetupItemBearerSUReqExtIETable struct{}

func ERABToBeSetupItemBearerSUReqExtIEs() ERABToBeSetupItemBearerSUReqExtIETable {
	return ERABToBeSetupItemBearerSUReqExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSetupItemBearerSUReqExtIETable.
func (ERABToBeSetupItemBearerSUReqExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSetupItemBearerSUReqExtIETable.
func (ERABToBeSetupItemBearerSUReqExtIETable) Table() s00.ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTable {
	return func() s00.ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTable {
		sealed := s00.ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoCorrelationID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(156), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Correlation-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-Correlation-ID"}}}
}

// CorrelationID returns the typed binding for the CorrelationID row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) CorrelationID() s28.ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding {
	return func() s28.ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding {
		sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding{}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldInfo(&sealed) = t.infoCorrelationID()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldCodec(&sealed) = func() s00.CorrelationIDValueCodec {
			sealed := s00.CorrelationIDValueCodec{}
			*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
			*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CorrelationID")
				var zero s28.ERABToBeSetupItemBearerSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(156), raw)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				value, ok := decoded.AsCorrelationID()
				if !ok {
					var empty s00.CorrelationID
					return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-Correlation-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowCorrelationID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCorrelationIDValueCodecFieldCapture(&sealed) = func(v s00.CorrelationID, options aper.DecodeState) (s00.CorrelationID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCorrelationID(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCorrelationIDValueCodecFieldCompare(&sealed) = func(v s00.CorrelationID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCorrelationID(&v, &s)
				s.End(f, root, false)
				return s.Plan(),

					s.BudgetValue()
			}
			*s00.BridgeCorrelationIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CorrelationID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldInject(&sealed) = func(value s00.CorrelationID) s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowCorrelationID(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsCorrelationID()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoSIPTOCorrelationID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(183), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Correlation-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-SIPTO-Correlation-ID"}}}
}

// SIPTOCorrelationID returns the typed binding for the SIPTOCorrelationID row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) SIPTOCorrelationID() s28.ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding {
	return func() s28.ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding {
		sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding{}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldInfo(&sealed) = t.infoSIPTOCorrelationID()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldCodec(&sealed) = func() s00.CorrelationIDValueCodec {
			sealed := s00.CorrelationIDValueCodec{}
			*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
			*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CorrelationID")
				var zero s28.ERABToBeSetupItemBearerSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(183), raw)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				value, ok := decoded.AsSIPTOCorrelationID()
				if !ok {
					var empty s00.CorrelationID
					return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-SIPTO-Correlation-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCorrelationIDValueCodecFieldCapture(&sealed) = func(v s00.CorrelationID, options aper.DecodeState) (s00.CorrelationID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCorrelationID(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCorrelationIDValueCodecFieldCompare(&sealed) = func(v s00.CorrelationID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCorrelationID(&v, &s)
				s.End(f, root, false)
				return s.Plan(),

					s.BudgetValue()
			}
			*s00.BridgeCorrelationIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CorrelationID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldInject(&sealed) = func(value s00.CorrelationID) s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsSIPTOCorrelationID()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoBearerType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(233), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BearerType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-BearerType"}}}
}

// BearerType returns the typed binding for the BearerType row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) BearerType() s28.ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding {
	return func() s28.ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding {
		sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding{}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldInfo(&sealed) = t.infoBearerType()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldCodec(&sealed) = func() s00.BearerTypeValueCodec {
			sealed := s00.BearerTypeValueCodec{}
			*s00.BridgeBearerTypeValueCodecFieldPath(&sealed) = "BearerType"
			*s00.BridgeBearerTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BearerType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.BearerType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("BearerType")
				var zero s28.ERABToBeSetupItemBearerSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(233), raw)
				if err != nil {
					var empty s00.BearerType
					return empty, err
				}
				value, ok := decoded.AsBearerType()
				if !ok {
					var empty s00.BearerType
					return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-BearerType: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeBearerTypeValueCodecFieldEncode(&sealed) = func(value s00.BearerType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowBearerType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeBearerTypeValueCodecFieldCapture(&sealed) = func(v s00.BearerType, options aper.DecodeState) (s00.BearerType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f :=
					s.Begin()
				s00.BridgeCaptureS1APBearerType(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeBearerTypeValueCodecFieldCompare(&sealed) = func(v s00.BearerType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APBearerType(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeBearerTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearerType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldInject(&sealed) = func(value s00.BearerType) s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowBearerType(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.BearerType, bool) {
			return value.AsBearerType()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoEthernetType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(305), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Ethernet-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-Ethernet-Type"}}}
}

// EthernetType returns the typed binding for the EthernetType row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) EthernetType() s28.ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding {
	return func() s28.ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding {
		sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding{}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldInfo(&sealed) = t.infoEthernetType()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldCodec(&sealed) = func() s00.EthernetTypeValueCodec {
			sealed := s00.EthernetTypeValueCodec{}
			*s00.BridgeEthernetTypeValueCodecFieldPath(&sealed) = "EthernetType"
			*s00.BridgeEthernetTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EthernetType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EthernetType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EthernetType")
				var zero s28.ERABToBeSetupItemBearerSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(305), raw)
				if err != nil {
					var empty s00.EthernetType
					return empty, err
				}
				value, ok := decoded.AsEthernetType()
				if !ok {
					var empty s00.EthernetType
					return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-Ethernet-Type: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEthernetTypeValueCodecFieldEncode(&sealed) = func(value s00.EthernetType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
					*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowEthernetType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeEthernetTypeValueCodecFieldCapture(&sealed) = func(v s00.EthernetType, options aper.DecodeState) (s00.EthernetType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APEthernetType(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeEthernetTypeValueCodecFieldCompare(&sealed) = func(v s00.EthernetType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APEthernetType(&v, &s)
				s.End(f, root, false)
				return s.Plan(),
					s.
						BudgetValue()
			}
			*s00.BridgeEthernetTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EthernetType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldInject(&sealed) = func(value s00.EthernetType) s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowEthernetType(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.EthernetType, bool) {
			return value.AsEthernetType()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoSecurityIndication() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(332), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-SecurityIndication"}}}
}

// SecurityIndication returns the typed binding for the SecurityIndication row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) SecurityIndication() ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding {
	return ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding{info: t.infoSecurityIndication(), codec: SecurityIndicationValueCodec{path: "SecurityIndication",
		decode: func(data []byte, options aper.DecodeState) (s28.SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero s28.ERABToBeSetupItemBearerSUReqExtIEsValue
			decoded, err := s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty s28.SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value s28.SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s28.SecurityIndication, options aper.DecodeState) (s28.SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v s28.SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s28.SecurityIndication) s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
		return func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
			sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
			*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
			*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s28.ERABToBeSetupItemBearerSUReqExtIEsValue) (*s28.SecurityIndication, bool) {
		return value.AsSecurityIndication()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (s28.ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(156):
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(183):
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SIPTO-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(233):
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-BearerType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(305):
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Ethernet-Type requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(332):
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return s28.ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
			sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
			*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = id
			*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldOpaque(&sealed) = opaque
			*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSetupItemBearerSUReqIETable struct{}

func ERABToBeSetupItemBearerSUReqIEs() ERABToBeSetupItemBearerSUReqIETable {
	return ERABToBeSetupItemBearerSUReqIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSetupItemBearerSUReqIETable.
func (ERABToBeSetupItemBearerSUReqIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSetupItemBearerSUReqIETable.
func (ERABToBeSetupItemBearerSUReqIETable) Table() s00.ERABToBeSetupItemBearerSUReqIEValueIETable {
	return func() s00.ERABToBeSetupItemBearerSUReqIEValueIETable {
		sealed := s00.ERABToBeSetupItemBearerSUReqIEValueIETable{}
		*s00.BridgeERABToBeSetupItemBearerSUReqIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSetupItemBearerSUReqIETable) infoERABToBeSetupItemBearerSUReq() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABToBeSetupItemBearerSUReqIEs().ID(), ID: s00.ProtocolIEID(17), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqIEs", Row: "id-E-RABToBeSetupItemBearerSUReq"}}}
}

// ERABToBeSetupItemBearerSUReq returns the typed binding for the ERABToBeSetupItemBearerSUReq row of ERABToBeSetupItemBearerSUReqIETable.
func (t ERABToBeSetupItemBearerSUReqIETable) ERABToBeSetupItemBearerSUReq() ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding {
	return ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding{info: t.infoERABToBeSetupItemBearerSUReq(), codec: ERABToBeSetupItemBearerSUReqValueCodec{path: "ERABToBeSetupItemBearerSUReq",
		decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABToBeSetupItemBearerSUReq
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeSetupItemBearerSUReq")
			var zero ERABToBeSetupItemBearerSUReqIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(17), raw)
			if err != nil {
				var empty ERABToBeSetupItemBearerSUReq
				return empty, err
			}
			value, ok := decoded.AsERABToBeSetupItemBearerSUReq()
			if !ok {
				var empty ERABToBeSetupItemBearerSUReq
				return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqIEs.id-E-RABToBeSetupItemBearerSUReq: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABToBeSetupItemBearerSUReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemBearerSUReqIEValue{id: s00.ProtocolIEID(17), rowERABToBeSetupItemBearerSUReq: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABToBeSetupItemBearerSUReq, options aper.DecodeState) (ERABToBeSetupItemBearerSUReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABToBeSetupItemBearerSUReq(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSetupItemBearerSUReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompareS1APERABToBeSetupItemBearerSUReq(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSetupItemBearerSUReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABToBeSetupItemBearerSUReq) ERABToBeSetupItemBearerSUReqIEValue {
		return ERABToBeSetupItemBearerSUReqIEValue{id: s00.ProtocolIEID(17), rowERABToBeSetupItemBearerSUReq: &value}
	}, get: func(value *ERABToBeSetupItemBearerSUReqIEValue) (*ERABToBeSetupItemBearerSUReq, bool) {
		return value.AsERABToBeSetupItemBearerSUReq()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSetupItemBearerSUReqIETable.
func (t ERABToBeSetupItemBearerSUReqIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABToBeSetupItemBearerSUReqIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(17):
		return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSetupItemBearerSUReq requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSetupItemBearerSUReqIEField{Id: id, Criticality: criticality, Value: ERABToBeSetupItemBearerSUReqIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSetupItemCtxtSUReqExtIETable struct{}

func ERABToBeSetupItemCtxtSUReqExtIEs() ERABToBeSetupItemCtxtSUReqExtIETable {
	return ERABToBeSetupItemCtxtSUReqExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSetupItemCtxtSUReqExtIETable.
func (ERABToBeSetupItemCtxtSUReqExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSetupItemCtxtSUReqExtIETable.
func (ERABToBeSetupItemCtxtSUReqExtIETable) Table() s00.ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTable {
	return func() s00.ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTable {
		sealed := s00.ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoCorrelationID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(156), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Correlation-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-Correlation-ID"}}}
}

// CorrelationID returns the typed binding for the CorrelationID row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) CorrelationID() s28.ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding {
	return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding {
		sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding{}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldInfo(&sealed) = t.infoCorrelationID()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldCodec(&sealed) = func() s00.CorrelationIDValueCodec {
			sealed := s00.CorrelationIDValueCodec{}
			*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
			*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CorrelationID")
				var zero s28.ERABToBeSetupItemCtxtSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(156), raw)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				value, ok := decoded.AsCorrelationID()
				if !ok {
					var empty s00.CorrelationID
					return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-Correlation-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowCorrelationID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCorrelationIDValueCodecFieldCapture(&sealed) = func(v s00.CorrelationID, options aper.DecodeState) (s00.CorrelationID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCorrelationID(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCorrelationIDValueCodecFieldCompare(&sealed) = func(v s00.CorrelationID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCorrelationID(&v, &s)
				s.End(f, root, false)
				return s.Plan(),

					s.BudgetValue()
			}
			*s00.BridgeCorrelationIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CorrelationID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldInject(&sealed) = func(value s00.CorrelationID) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowCorrelationID(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsCorrelationID()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoSIPTOCorrelationID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(183), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Correlation-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-SIPTO-Correlation-ID"}}}
}

// SIPTOCorrelationID returns the typed binding for the SIPTOCorrelationID row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) SIPTOCorrelationID() s28.ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding {
	return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding {
		sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding{}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldInfo(&sealed) = t.infoSIPTOCorrelationID()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldCodec(&sealed) = func() s00.CorrelationIDValueCodec {
			sealed := s00.CorrelationIDValueCodec{}
			*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
			*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CorrelationID")
				var zero s28.ERABToBeSetupItemCtxtSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(183), raw)
				if err != nil {
					var empty s00.CorrelationID
					return empty, err
				}
				value, ok := decoded.AsSIPTOCorrelationID()
				if !ok {
					var empty s00.CorrelationID
					return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-SIPTO-Correlation-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCorrelationIDValueCodecFieldCapture(&sealed) = func(v s00.CorrelationID, options aper.DecodeState) (s00.CorrelationID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCorrelationID(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCorrelationIDValueCodecFieldCompare(&sealed) = func(v s00.CorrelationID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCorrelationID(&v, &s)
				s.End(f, root, false)
				return s.Plan(),

					s.BudgetValue()
			}
			*s00.BridgeCorrelationIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CorrelationID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldInject(&sealed) = func(value s00.CorrelationID) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsSIPTOCorrelationID()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoBearerType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(233), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BearerType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-BearerType"}}}
}

// BearerType returns the typed binding for the BearerType row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) BearerType() s28.ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding {
	return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding {
		sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding{}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldInfo(&sealed) = t.infoBearerType()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldCodec(&sealed) = func() s00.BearerTypeValueCodec {
			sealed := s00.BearerTypeValueCodec{}
			*s00.BridgeBearerTypeValueCodecFieldPath(&sealed) = "BearerType"
			*s00.BridgeBearerTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BearerType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.BearerType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("BearerType")
				var zero s28.ERABToBeSetupItemCtxtSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(233), raw)
				if err != nil {
					var empty s00.BearerType
					return empty, err
				}
				value, ok := decoded.AsBearerType()
				if !ok {
					var empty s00.BearerType
					return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-BearerType: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeBearerTypeValueCodecFieldEncode(&sealed) = func(value s00.BearerType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowBearerType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeBearerTypeValueCodecFieldCapture(&sealed) = func(v s00.BearerType, options aper.DecodeState) (s00.BearerType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f :=
					s.Begin()
				s00.BridgeCaptureS1APBearerType(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeBearerTypeValueCodecFieldCompare(&sealed) = func(v s00.BearerType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APBearerType(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeBearerTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearerType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldInject(&sealed) = func(value s00.BearerType) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowBearerType(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.BearerType, bool) {
			return value.AsBearerType()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoEthernetType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(305), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Ethernet-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-Ethernet-Type"}}}
}

// EthernetType returns the typed binding for the EthernetType row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) EthernetType() s28.ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding {
	return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding {
		sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding{}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldInfo(&sealed) = t.infoEthernetType()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldCodec(&sealed) = func() s00.EthernetTypeValueCodec {
			sealed := s00.EthernetTypeValueCodec{}
			*s00.BridgeEthernetTypeValueCodecFieldPath(&sealed) = "EthernetType"
			*s00.BridgeEthernetTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EthernetType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EthernetType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EthernetType")
				var zero s28.ERABToBeSetupItemCtxtSUReqExtIEsValue
				decoded, err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(305), raw)
				if err != nil {
					var empty s00.EthernetType
					return empty, err
				}
				value, ok := decoded.AsEthernetType()
				if !ok {
					var empty s00.EthernetType
					return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-Ethernet-Type: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEthernetTypeValueCodecFieldEncode(&sealed) = func(value s00.EthernetType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
					sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
					*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowEthernetType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeEthernetTypeValueCodecFieldCapture(&sealed) = func(v s00.EthernetType, options aper.DecodeState) (s00.EthernetType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APEthernetType(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeEthernetTypeValueCodecFieldCompare(&sealed) = func(v s00.EthernetType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APEthernetType(&v, &s)
				s.End(f, root, false)
				return s.Plan(),
					s.
						BudgetValue()
			}
			*s00.BridgeEthernetTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EthernetType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldInject(&sealed) = func(value s00.EthernetType) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowEthernetType(&sealed) = &value
				return sealed
			}()
		}
		*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldGet(&sealed) = func(value *s28.ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.EthernetType, bool) {
			return value.AsEthernetType()
		}
		return sealed
	}()
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoSecurityIndication() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(332), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-SecurityIndication"}}}
}

// SecurityIndication returns the typed binding for the SecurityIndication row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) SecurityIndication() ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding {
	return ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding{info: t.infoSecurityIndication(), codec: SecurityIndicationValueCodec{path: "SecurityIndication",
		decode: func(data []byte, options aper.DecodeState) (s28.SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero s28.ERABToBeSetupItemCtxtSUReqExtIEsValue
			decoded, err := s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodDecode(zero, s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty s28.SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value s28.SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodEncodeFresh((func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s28.SecurityIndication, options aper.DecodeState) (s28.SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v s28.SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s28.SecurityIndication) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
		return func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
			*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
			*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s28.ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s28.SecurityIndication, bool) {
		return value.AsSecurityIndication()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(156):
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(183):
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SIPTO-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(233):
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-BearerType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(305):
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Ethernet-Type requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(332):
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return s28.ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			sealed := s28.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
			*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = id
			*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldOpaque(&sealed) = opaque
			*s28.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSetupItemCtxtSUReqIETable struct{}

func ERABToBeSetupItemCtxtSUReqIEs() ERABToBeSetupItemCtxtSUReqIETable {
	return ERABToBeSetupItemCtxtSUReqIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSetupItemCtxtSUReqIETable.
func (ERABToBeSetupItemCtxtSUReqIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSetupItemCtxtSUReqIETable.
func (ERABToBeSetupItemCtxtSUReqIETable) Table() s00.ERABToBeSetupItemCtxtSUReqIEValueIETable {
	return func() s00.ERABToBeSetupItemCtxtSUReqIEValueIETable {
		sealed := s00.ERABToBeSetupItemCtxtSUReqIEValueIETable{}
		*s00.BridgeERABToBeSetupItemCtxtSUReqIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSetupItemCtxtSUReqIETable) infoERABToBeSetupItemCtxtSUReq() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABToBeSetupItemCtxtSUReqIEs().ID(), ID: s00.ProtocolIEID(52), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqIEs", Row: "id-E-RABToBeSetupItemCtxtSUReq"}}}
}

// ERABToBeSetupItemCtxtSUReq returns the typed binding for the ERABToBeSetupItemCtxtSUReq row of ERABToBeSetupItemCtxtSUReqIETable.
func (t ERABToBeSetupItemCtxtSUReqIETable) ERABToBeSetupItemCtxtSUReq() ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding {
	return ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding{info: t.infoERABToBeSetupItemCtxtSUReq(), codec: ERABToBeSetupItemCtxtSUReqValueCodec{path: "ERABToBeSetupItemCtxtSUReq",
		decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABToBeSetupItemCtxtSUReq
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeSetupItemCtxtSUReq")
			var zero ERABToBeSetupItemCtxtSUReqIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(52), raw)
			if err != nil {
				var empty ERABToBeSetupItemCtxtSUReq
				return empty, err
			}
			value, ok := decoded.AsERABToBeSetupItemCtxtSUReq()
			if !ok {
				var empty ERABToBeSetupItemCtxtSUReq
				return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqIEs.id-E-RABToBeSetupItemCtxtSUReq: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABToBeSetupItemCtxtSUReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemCtxtSUReqIEValue{id: s00.ProtocolIEID(52), rowERABToBeSetupItemCtxtSUReq: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABToBeSetupItemCtxtSUReq, options aper.DecodeState) (ERABToBeSetupItemCtxtSUReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABToBeSetupItemCtxtSUReq(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSetupItemCtxtSUReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABToBeSetupItemCtxtSUReq(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSetupItemCtxtSUReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABToBeSetupItemCtxtSUReq) ERABToBeSetupItemCtxtSUReqIEValue {
		return ERABToBeSetupItemCtxtSUReqIEValue{id: s00.ProtocolIEID(52), rowERABToBeSetupItemCtxtSUReq: &value}
	}, get: func(value *ERABToBeSetupItemCtxtSUReqIEValue) (*ERABToBeSetupItemCtxtSUReq, bool) {
		return value.AsERABToBeSetupItemCtxtSUReq()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSetupItemCtxtSUReqIETable.
func (t ERABToBeSetupItemCtxtSUReqIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABToBeSetupItemCtxtSUReqIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(52):
		return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSetupItemCtxtSUReq requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSetupItemCtxtSUReqIEField{Id: id, Criticality: criticality, Value: ERABToBeSetupItemCtxtSUReqIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSetupItemHOReqExtIETable struct{}

func ERABToBeSetupItemHOReqExtIEs() ERABToBeSetupItemHOReqExtIETable {
	return ERABToBeSetupItemHOReqExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSetupItemHOReqExtIETable.
func (ERABToBeSetupItemHOReqExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemHOReq-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSetupItemHOReqExtIETable.
func (ERABToBeSetupItemHOReqExtIETable) Table() s00.ERABToBeSetupItemHOReqExtIEsValueExtensionTable {
	return func() s00.ERABToBeSetupItemHOReqExtIEsValueExtensionTable {
		sealed := s00.ERABToBeSetupItemHOReqExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeSetupItemHOReqExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSetupItemHOReqExtIETable) infoDataForwardingNotPossible() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemHOReqExtIEs().ID(), ID: s00.ProtocolExtensionID(143), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Data-Forwarding-Not-Possible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemHOReq-ExtIEs", Row: "id-Data-Forwarding-Not-Possible"}}}
}

// DataForwardingNotPossible returns the typed binding for the DataForwardingNotPossible row of ERABToBeSetupItemHOReqExtIETable.
func (t ERABToBeSetupItemHOReqExtIETable) DataForwardingNotPossible() ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding {
	return ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding{info: t.infoDataForwardingNotPossible(), codec: func() s00.DataForwardingNotPossibleValueCodec {
		sealed := s00.DataForwardingNotPossibleValueCodec{}
		*s00.BridgeDataForwardingNotPossibleValueCodecFieldPath(&sealed) = "DataForwardingNotPossible"
		*s00.BridgeDataForwardingNotPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DataForwardingNotPossible, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DataForwardingNotPossible
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DataForwardingNotPossible")
			var zero ERABToBeSetupItemHOReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(143), raw)
			if err != nil {
				var empty s00.DataForwardingNotPossible
				return empty, err
			}
			value, ok := decoded.AsDataForwardingNotPossible()
			if !ok {
				var empty s00.DataForwardingNotPossible
				return empty, fmt.Errorf("binding E-RABToBeSetupItemHOReq-ExtIEs.id-Data-Forwarding-Not-Possible: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDataForwardingNotPossibleValueCodecFieldEncode(&sealed) = func(value s00.DataForwardingNotPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(143), rowDataForwardingNotPossible: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeDataForwardingNotPossibleValueCodecFieldCapture(&sealed) = func(v s00.DataForwardingNotPossible, options aper.DecodeState) (s00.DataForwardingNotPossible, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APDataForwardingNotPossible(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s00.BridgeDataForwardingNotPossibleValueCodecFieldCompare(&sealed) = func(v s00.DataForwardingNotPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APDataForwardingNotPossible(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeDataForwardingNotPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DataForwardingNotPossible"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.DataForwardingNotPossible) ERABToBeSetupItemHOReqExtIEsValue {
			return ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(143), rowDataForwardingNotPossible: &value}
		}, get: func(value *ERABToBeSetupItemHOReqExtIEsValue) (*s00.DataForwardingNotPossible, bool) {
			return value.AsDataForwardingNotPossible()
		}}
}
func (ERABToBeSetupItemHOReqExtIETable) infoBearerType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemHOReqExtIEs().ID(), ID: s00.ProtocolExtensionID(233), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BearerType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemHOReq-ExtIEs", Row: "id-BearerType"}}}
}

// BearerType returns the typed binding for the BearerType row of ERABToBeSetupItemHOReqExtIETable.
func (t ERABToBeSetupItemHOReqExtIETable) BearerType() ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding {
	return ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding{info: t.infoBearerType(), codec: func() s00.BearerTypeValueCodec {
		sealed := s00.BearerTypeValueCodec{}
		*s00.BridgeBearerTypeValueCodecFieldPath(&sealed) = "BearerType"
		*s00.BridgeBearerTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BearerType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.BearerType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearerType")
			var zero ERABToBeSetupItemHOReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(233), raw)
			if err != nil {
				var empty s00.BearerType
				return empty, err
			}
			value, ok := decoded.AsBearerType()
			if !ok {
				var empty s00.BearerType
				return empty, fmt.Errorf("binding E-RABToBeSetupItemHOReq-ExtIEs.id-BearerType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeBearerTypeValueCodecFieldEncode(&sealed) = func(value s00.BearerType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(233), rowBearerType: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeBearerTypeValueCodecFieldCapture(&sealed) = func(v s00.BearerType, options aper.DecodeState) (s00.BearerType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APBearerType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBearerTypeValueCodecFieldCompare(&sealed) = func(v s00.BearerType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APBearerType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeBearerTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearerType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.BearerType) ERABToBeSetupItemHOReqExtIEsValue {
			return ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(233), rowBearerType: &value}
		}, get: func(value *ERABToBeSetupItemHOReqExtIEsValue) (*s00.BearerType, bool) { return value.AsBearerType() }}
}
func (ERABToBeSetupItemHOReqExtIETable) infoEthernetType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemHOReqExtIEs().ID(), ID: s00.ProtocolExtensionID(305), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Ethernet-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemHOReq-ExtIEs", Row: "id-Ethernet-Type"}}}
}

// EthernetType returns the typed binding for the EthernetType row of ERABToBeSetupItemHOReqExtIETable.
func (t ERABToBeSetupItemHOReqExtIETable) EthernetType() ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding {
	return ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding{info: t.infoEthernetType(), codec: func() s00.EthernetTypeValueCodec {
		sealed := s00.EthernetTypeValueCodec{}
		*s00.BridgeEthernetTypeValueCodecFieldPath(&sealed) = "EthernetType"
		*s00.BridgeEthernetTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EthernetType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EthernetType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EthernetType")
			var zero ERABToBeSetupItemHOReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(305), raw)
			if err != nil {
				var empty s00.EthernetType
				return empty, err
			}
			value, ok := decoded.AsEthernetType()
			if !ok {
				var empty s00.EthernetType
				return empty, fmt.Errorf("binding E-RABToBeSetupItemHOReq-ExtIEs.id-Ethernet-Type: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEthernetTypeValueCodecFieldEncode(&sealed) = func(value s00.EthernetType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(305), rowEthernetType: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEthernetTypeValueCodecFieldCapture(&sealed) = func(v s00.EthernetType, options aper.DecodeState) (s00.EthernetType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEthernetType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEthernetTypeValueCodecFieldCompare(&sealed) = func(v s00.EthernetType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEthernetType(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s00.BridgeEthernetTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EthernetType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EthernetType) ERABToBeSetupItemHOReqExtIEsValue {
			return ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(305), rowEthernetType: &value}
		}, get: func(value *ERABToBeSetupItemHOReqExtIEsValue) (*s00.EthernetType, bool) {
			return value.AsEthernetType()
		}}
}
func (ERABToBeSetupItemHOReqExtIETable) infoSecurityIndication() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemHOReqExtIEs().ID(), ID: s00.ProtocolExtensionID(332), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemHOReq-ExtIEs", Row: "id-SecurityIndication"}}}
}

// SecurityIndication returns the typed binding for the SecurityIndication row of ERABToBeSetupItemHOReqExtIETable.
func (t ERABToBeSetupItemHOReqExtIETable) SecurityIndication() ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding {
	return ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding{info: t.infoSecurityIndication(), codec: SecurityIndicationValueCodec{path: "SecurityIndication",
		decode: func(data []byte, options aper.DecodeState) (s28.SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero ERABToBeSetupItemHOReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty s28.SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSetupItemHOReq-ExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value s28.SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s28.SecurityIndication, options aper.DecodeState) (s28.SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v s28.SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s28.SecurityIndication) ERABToBeSetupItemHOReqExtIEsValue {
		return ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}
	}, get: func(value *ERABToBeSetupItemHOReqExtIEsValue) (*s28.SecurityIndication, bool) {
		return value.AsSecurityIndication()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSetupItemHOReqExtIETable.
func (t ERABToBeSetupItemHOReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeSetupItemHOReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(143):
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Data-Forwarding-Not-Possible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(233):
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-BearerType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(305):
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Ethernet-Type requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(332):
		return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSetupItemHOReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSetupItemHOReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABToBeSetupItemHOReqExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSwitchedDLItemExtIETable struct{}

func ERABToBeSwitchedDLItemExtIEs() ERABToBeSwitchedDLItemExtIETable {
	return ERABToBeSwitchedDLItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSwitchedDLItemExtIETable.
func (ERABToBeSwitchedDLItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSwitchedDLItemExtIETable.
func (ERABToBeSwitchedDLItemExtIETable) Table() s00.ERABToBeSwitchedDLItemExtIEsValueExtensionTable {
	return func() s00.ERABToBeSwitchedDLItemExtIEsValueExtensionTable {
		sealed := s00.ERABToBeSwitchedDLItemExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeSwitchedDLItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSwitchedDLItemExtIETable) infoSecurityIndication() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSwitchedDLItemExtIEs().ID(), ID: s00.ProtocolExtensionID(332), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLItem-ExtIEs", Row: "id-SecurityIndication"}}}
}

// SecurityIndication returns the typed binding for the SecurityIndication row of ERABToBeSwitchedDLItemExtIETable.
func (t ERABToBeSwitchedDLItemExtIETable) SecurityIndication() ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding {
	return ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding{info: t.infoSecurityIndication(), codec: SecurityIndicationValueCodec{path: "SecurityIndication",
		decode: func(data []byte, options aper.DecodeState) (s28.SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero ERABToBeSwitchedDLItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty s28.SecurityIndication
				return empty, err
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty s28.SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSwitchedDLItem-ExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value s28.SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSwitchedDLItemExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s28.SecurityIndication, options aper.DecodeState) (s28.SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v s28.SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s28.SecurityIndication) ERABToBeSwitchedDLItemExtIEsValue {
		return ERABToBeSwitchedDLItemExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}
	}, get: func(value *ERABToBeSwitchedDLItemExtIEsValue) (*s28.SecurityIndication, bool) {
		return value.AsSecurityIndication()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSwitchedDLItemExtIETable.
func (t ERABToBeSwitchedDLItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeSwitchedDLItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(332):
		return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSwitchedDLItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSwitchedDLItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABToBeSwitchedDLItemExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeUpdatedItemIETable struct{}

func ERABToBeUpdatedItemIEs() ERABToBeUpdatedItemIETable { return ERABToBeUpdatedItemIETable{} }

// ID returns the ASN.1 object-set identity of ERABToBeUpdatedItemIETable.
func (ERABToBeUpdatedItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeUpdatedItemIETable.
func (ERABToBeUpdatedItemIETable) Table() s00.ERABToBeUpdatedItemIEValueIETable {
	return func() s00.ERABToBeUpdatedItemIEValueIETable {
		sealed := s00.ERABToBeUpdatedItemIEValueIETable{}
		*s00.BridgeERABToBeUpdatedItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeUpdatedItemIETable) infoERABToBeUpdatedItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABToBeUpdatedItemIEs().ID(), ID: s00.ProtocolIEID(342), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedItemIEs", Row: "id-E-RABToBeUpdatedItem"}}}
}

// ERABToBeUpdatedItem returns the typed binding for the ERABToBeUpdatedItem row of ERABToBeUpdatedItemIETable.
func (t ERABToBeUpdatedItemIETable) ERABToBeUpdatedItem() ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding {
	return ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding{info: t.infoERABToBeUpdatedItem(), codec: ERABToBeUpdatedItemValueCodec{path: "ERABToBeUpdatedItem",
		decode: func(data []byte, options aper.DecodeState) (ERABToBeUpdatedItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABToBeUpdatedItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeUpdatedItem")
			var zero ERABToBeUpdatedItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(342), raw)
			if err != nil {
				var empty ERABToBeUpdatedItem
				return empty, err
			}
			value, ok := decoded.AsERABToBeUpdatedItem()
			if !ok {
				var empty ERABToBeUpdatedItem
				return empty, fmt.Errorf("binding E-RABToBeUpdatedItemIEs.id-E-RABToBeUpdatedItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABToBeUpdatedItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeUpdatedItemIEValue{id: s00.ProtocolIEID(342), rowERABToBeUpdatedItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABToBeUpdatedItem, options aper.DecodeState) (ERABToBeUpdatedItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABToBeUpdatedItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeUpdatedItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABToBeUpdatedItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeUpdatedItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABToBeUpdatedItem) ERABToBeUpdatedItemIEValue {
		return ERABToBeUpdatedItemIEValue{id: s00.ProtocolIEID(342), rowERABToBeUpdatedItem: &value}
	}, get: func(value *ERABToBeUpdatedItemIEValue) (*ERABToBeUpdatedItem, bool) {
		return value.AsERABToBeUpdatedItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeUpdatedItemIETable.
func (t ERABToBeUpdatedItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABToBeUpdatedItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeUpdatedItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(342):
		return ERABToBeUpdatedItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeUpdatedItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeUpdatedItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeUpdatedItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeUpdatedItemIEField{Id: id, Criticality: criticality, Value: ERABToBeUpdatedItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// BearerTypeCodec binds the complete APER value type.
func BearerTypeCodec() s00.BearerTypeValueCodec {
	return ERABToBeSetupItemBearerSUReqExtIEs().BearerType().Codec()
}

// CorrelationIDCodec binds the complete APER value type.
func CorrelationIDCodec() s00.CorrelationIDValueCodec {
	return ERABToBeSetupItemBearerSUReqExtIEs().CorrelationID().Codec()
}

// DAPSRequestInfoCodec binds the complete APER value type.
func DAPSRequestInfoCodec() s14.DAPSRequestInfoValueCodec {
	return ERABInformationListItemExtIEs().DAPSRequestInfo().Codec()
}

// DataForwardingNotPossibleCodec binds the complete APER value type.
func DataForwardingNotPossibleCodec() s00.DataForwardingNotPossibleValueCodec {
	return ERABToBeSetupItemHOReqExtIEs().DataForwardingNotPossible().Codec()
}

// ERABInformationListItemCodec binds the complete APER value type.
func ERABInformationListItemCodec() ERABInformationListItemValueCodec {
	return ERABInformationListIEs().ERABInformationListItem().Codec()
}

// ERABToBeSetupItemBearerSUReqCodec binds the complete APER value type.
func ERABToBeSetupItemBearerSUReqCodec() ERABToBeSetupItemBearerSUReqValueCodec {
	return ERABToBeSetupItemBearerSUReqIEs().ERABToBeSetupItemBearerSUReq().Codec()
}

// ERABToBeSetupItemCtxtSUReqCodec binds the complete APER value type.
func ERABToBeSetupItemCtxtSUReqCodec() ERABToBeSetupItemCtxtSUReqValueCodec {
	return ERABToBeSetupItemCtxtSUReqIEs().ERABToBeSetupItemCtxtSUReq().Codec()
}

// ERABToBeUpdatedItemCodec binds the complete APER value type.
func ERABToBeUpdatedItemCodec() ERABToBeUpdatedItemValueCodec {
	return ERABToBeUpdatedItemIEs().ERABToBeUpdatedItem().Codec()
}

// EthernetTypeCodec binds the complete APER value type.
func EthernetTypeCodec() s00.EthernetTypeValueCodec {
	return ERABToBeSetupItemBearerSUReqExtIEs().EthernetType().Codec()
}

// SecurityIndicationCodec binds the complete APER value type.
func SecurityIndicationCodec() SecurityIndicationValueCodec {
	return ERABInformationListItemExtIEs().SecurityIndication().Codec()
}

// TransportLayerAddressCodec binds the complete APER value type.
func TransportLayerAddressCodec() s02.TransportLayerAddressValueCodec {
	return ERABInformationListItemExtIEs().SourceTransportLayerAddress().Codec()
}
func BridgeERABInformationListAPERValueFieldContext(v *ERABInformationListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListAPERValueFieldReceived(v *ERABInformationListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListAPERValueFieldReplay(v *ERABInformationListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListAPERValueFieldWithoutReplay(v *ERABInformationListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListERABInformationListItemIEBindingFieldCodec(v *ERABInformationListERABInformationListItemIEBinding) *ERABInformationListItemValueCodec {
	return &v.codec
}
func BridgeERABInformationListERABInformationListItemIEBindingFieldGet(v *ERABInformationListERABInformationListItemIEBinding) *func(*ERABInformationListIEValue) (*ERABInformationListItem, bool) {
	return &v.get
}
func BridgeERABInformationListERABInformationListItemIEBindingFieldInfo(v *ERABInformationListERABInformationListItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABInformationListERABInformationListItemIEBindingFieldInject(v *ERABInformationListERABInformationListItemIEBinding) *func(ERABInformationListItem) ERABInformationListIEValue {
	return &v.inject
}
func BridgeERABInformationListIEContainerAPERValueFieldContext(v *ERABInformationListIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEContainerAPERValueFieldReceived(v *ERABInformationListIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListIEContainerAPERValueFieldReplay(v *ERABInformationListIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListIEContainerAPERValueFieldWithoutReplay(v *ERABInformationListIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListIEContainerValueCodecFieldCapture(v *ERABInformationListIEContainerValueCodec) *func(ERABInformationListIEContainer, aper.DecodeState) (ERABInformationListIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListIEContainerValueCodecFieldCompare(v *ERABInformationListIEContainerValueCodec) *func(ERABInformationListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListIEContainerValueCodecFieldContext(v *ERABInformationListIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEContainerValueCodecFieldDecode(v *ERABInformationListIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListIEContainer, error) {
	return &v.decode
}
func BridgeERABInformationListIEContainerValueCodecFieldEncode(v *ERABInformationListIEContainerValueCodec) *func(ERABInformationListIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListIEContainerValueCodecFieldPath(v *ERABInformationListIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListIEContainerValueCodecMethodEncodeBudgetValue(v ERABInformationListIEContainerValueCodec, a0 ERABInformationListIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListIEContainerValueCodecMethodEncodeChanged(v ERABInformationListIEContainerValueCodec, a0 ERABInformationListIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListIEFieldAPERValueFieldContext(v *ERABInformationListIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEFieldAPERValueFieldReceived(v *ERABInformationListIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListIEFieldAPERValueFieldReplay(v *ERABInformationListIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListIEFieldAPERValueFieldWithoutReplay(v *ERABInformationListIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListIEFieldFieldReceived(v *ERABInformationListIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABInformationListIEFieldFieldReplay(v *ERABInformationListIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListIEFieldFieldStream(v *ERABInformationListIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABInformationListIEFieldFieldWithoutReplay(v *ERABInformationListIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListIEFieldMethodMarshalAPERTo(v *ERABInformationListIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABInformationListIEFieldMethodUnmarshalAPERFrom(v *ERABInformationListIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABInformationListIEFieldValueCodecFieldCapture(v *ERABInformationListIEFieldValueCodec) *func(ERABInformationListIEField, aper.DecodeState) (ERABInformationListIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListIEFieldValueCodecFieldCompare(v *ERABInformationListIEFieldValueCodec) *func(ERABInformationListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListIEFieldValueCodecFieldContext(v *ERABInformationListIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEFieldValueCodecFieldDecode(v *ERABInformationListIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListIEField, error) {
	return &v.decode
}
func BridgeERABInformationListIEFieldValueCodecFieldEncode(v *ERABInformationListIEFieldValueCodec) *func(ERABInformationListIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListIEFieldValueCodecFieldPath(v *ERABInformationListIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListIEFieldValueCodecMethodEncodeBudgetValue(v ERABInformationListIEFieldValueCodec, a0 ERABInformationListIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListIEFieldValueCodecMethodEncodeChanged(v ERABInformationListIEFieldValueCodec, a0 ERABInformationListIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListIETableMethodInfoERABInformationListItem(v ERABInformationListIETable) s00.FieldInfo {
	return v.infoERABInformationListItem()
}
func BridgeERABInformationListIEValueERABIEContainerListAPERValueFieldContext(v *ERABInformationListIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEValueERABIEContainerListAPERValueFieldReceived(v *ERABInformationListIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListIEValueERABIEContainerListAPERValueFieldReplay(v *ERABInformationListIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABInformationListIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecFieldCapture(v *ERABInformationListIEValueERABIEContainerListValueCodec) *func(ERABInformationListIEValueERABIEContainerList, aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecFieldCompare(v *ERABInformationListIEValueERABIEContainerListValueCodec) *func(ERABInformationListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecFieldContext(v *ERABInformationListIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecFieldDecode(v *ERABInformationListIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecFieldEncode(v *ERABInformationListIEValueERABIEContainerListValueCodec) *func(ERABInformationListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecFieldPath(v *ERABInformationListIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABInformationListIEValueERABIEContainerListValueCodec, a0 ERABInformationListIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABInformationListIEValueERABIEContainerListValueCodec, a0 ERABInformationListIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListIEValueFieldId(v *ERABInformationListIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABInformationListIEValueFieldIsOpaque(v *ERABInformationListIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABInformationListIEValueFieldOpaque(v *ERABInformationListIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABInformationListIEValueFieldReceived(v *ERABInformationListIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListIEValueFieldReplay(v *ERABInformationListIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListIEValueFieldRowERABInformationListItem(v *ERABInformationListIEValue) **ERABInformationListItem {
	return &v.rowERABInformationListItem
}
func BridgeERABInformationListIEValueMethodCaptureSemantics(v ERABInformationListIEValue, a0 aper.SemanticCapture) ERABInformationListIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABInformationListIEValueMethodCompareSemantics(v ERABInformationListIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABInformationListIEValueMethodDecode(v ERABInformationListIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABInformationListIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABInformationListIEValueMethodEncode(v ERABInformationListIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABInformationListIEValueMethodEncodeFresh(v ERABInformationListIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABInformationListIEValueMethodMatchesID(v ERABInformationListIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABInformationListIEValueMethodReason(v ERABInformationListIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABInformationListIEValueMethodRule(v ERABInformationListIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABInformationListIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABInformationListIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABInformationListIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABInformationListIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) *func(ERABInformationListIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABInformationListIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) *func(ERABInformationListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) *func(ERABInformationListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABInformationListIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABInformationListIEValueProtocolErrorIEContainerListValueCodec, a0 ERABInformationListIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABInformationListIEValueProtocolErrorIEContainerListValueCodec, a0 ERABInformationListIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABInformationListIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABInformationListIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABInformationListIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABInformationListIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABInformationListIEValueProtocolIEContainerListValueCodec) *func(ERABInformationListIEValueProtocolIEContainerList, aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABInformationListIEValueProtocolIEContainerListValueCodec) *func(ERABInformationListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABInformationListIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABInformationListIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABInformationListIEValueProtocolIEContainerListValueCodec) *func(ERABInformationListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABInformationListIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABInformationListIEValueProtocolIEContainerListValueCodec, a0 ERABInformationListIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABInformationListIEValueProtocolIEContainerListValueCodec, a0 ERABInformationListIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListItemAPERValueFieldContext(v *ERABInformationListItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListItemAPERValueFieldReceived(v *ERABInformationListItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListItemAPERValueFieldReplay(v *ERABInformationListItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListItemAPERValueFieldWithoutReplay(v *ERABInformationListItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListItemExtIETableMethodInfoDAPSRequestInfo(v ERABInformationListItemExtIETable) s00.ExtensionInfo {
	return v.infoDAPSRequestInfo()
}
func BridgeERABInformationListItemExtIETableMethodInfoSecurityIndication(v ERABInformationListItemExtIETable) s00.ExtensionInfo {
	return v.infoSecurityIndication()
}
func BridgeERABInformationListItemExtIETableMethodInfoSourceNodeTransportLayerAddress(v ERABInformationListItemExtIETable) s00.ExtensionInfo {
	return v.infoSourceNodeTransportLayerAddress()
}
func BridgeERABInformationListItemExtIETableMethodInfoSourceTransportLayerAddress(v ERABInformationListItemExtIETable) s00.ExtensionInfo {
	return v.infoSourceTransportLayerAddress()
}
func BridgeERABInformationListItemExtIEsSecurityIndicationExtBindingFieldCodec(v *ERABInformationListItemExtIEsSecurityIndicationExtBinding) *SecurityIndicationValueCodec {
	return &v.codec
}
func BridgeERABInformationListItemExtIEsSecurityIndicationExtBindingFieldGet(v *ERABInformationListItemExtIEsSecurityIndicationExtBinding) *func(*s28.ERABInformationListItemExtIEsValue) (*s28.SecurityIndication, bool) {
	return &v.get
}
func BridgeERABInformationListItemExtIEsSecurityIndicationExtBindingFieldInfo(v *ERABInformationListItemExtIEsSecurityIndicationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABInformationListItemExtIEsSecurityIndicationExtBindingFieldInject(v *ERABInformationListItemExtIEsSecurityIndicationExtBinding) *func(s28.SecurityIndication) s28.ERABInformationListItemExtIEsValue {
	return &v.inject
}
func BridgeERABInformationListItemFieldExtCount(v *ERABInformationListItem) *int64 {
	return &v.extCount
}
func BridgeERABInformationListItemFieldExtData(v *ERABInformationListItem) *[][]byte {
	return &v.extData
}
func BridgeERABInformationListItemFieldExtOrigin(v *ERABInformationListItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABInformationListItemFieldExtPresent(v *ERABInformationListItem) *[]bool {
	return &v.extPresent
}
func BridgeERABInformationListItemFieldExtWire(v *ERABInformationListItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABInformationListItemFieldIEExtensionsIndef(v *ERABInformationListItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABInformationListItemFieldPerExtPadding(v *ERABInformationListItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABInformationListItemFieldPerPadding(v *ERABInformationListItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABInformationListItemFieldReceived(v *ERABInformationListItem) *bool { return &v.received }
func BridgeERABInformationListItemFieldReceivedAbsolute(v *ERABInformationListItem) *bool {
	return &v.receivedAbsolute
}
func BridgeERABInformationListItemFieldReceivedBytes(v *ERABInformationListItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABInformationListItemFieldReceivedLocation(v *ERABInformationListItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABInformationListItemFieldReplay(v *ERABInformationListItem) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListItemFieldStream(v *ERABInformationListItem) *aper.WireSpan {
	return &v.stream
}
func BridgeERABInformationListItemFieldWithoutReplay(v *ERABInformationListItem) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListItemMethodMarshalAPERBudget(v *ERABInformationListItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABInformationListItemMethodMarshalAPERBudgetValue(v *ERABInformationListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABInformationListItemMethodMarshalAPERChanged(v *ERABInformationListItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABInformationListItemMethodMarshalAPERChangedValue(v *ERABInformationListItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABInformationListItemMethodMarshalAPERLegacy(v *ERABInformationListItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABInformationListItemMethodMarshalAPERNewValue(v *ERABInformationListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABInformationListItemMethodMarshalAPERPlanned(v *ERABInformationListItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABInformationListItemMethodMarshalAPERTo(v *ERABInformationListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABInformationListItemMethodUnmarshalAPERFrom(v *ERABInformationListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABInformationListItemMethodUnmarshalAPERLegacy(v *ERABInformationListItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABInformationListItemMethodUnmarshalAPERWithOptions(v *ERABInformationListItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABInformationListItemValueCodecFieldCapture(v *ERABInformationListItemValueCodec) *func(ERABInformationListItem, aper.DecodeState) (ERABInformationListItem, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListItemValueCodecFieldCompare(v *ERABInformationListItemValueCodec) *func(ERABInformationListItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListItemValueCodecFieldContext(v *ERABInformationListItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListItemValueCodecFieldDecode(v *ERABInformationListItemValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListItem, error) {
	return &v.decode
}
func BridgeERABInformationListItemValueCodecFieldEncode(v *ERABInformationListItemValueCodec) *func(ERABInformationListItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListItemValueCodecFieldPath(v *ERABInformationListItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListItemValueCodecMethodEncodeBudgetValue(v ERABInformationListItemValueCodec, a0 ERABInformationListItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListItemValueCodecMethodEncodeChanged(v ERABInformationListItemValueCodec, a0 ERABInformationListItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListValueCodecFieldCapture(v *ERABInformationListValueCodec) *func(ERABInformationList, aper.DecodeState) (ERABInformationList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListValueCodecFieldCompare(v *ERABInformationListValueCodec) *func(ERABInformationList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListValueCodecFieldContext(v *ERABInformationListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListValueCodecFieldDecode(v *ERABInformationListValueCodec) *func([]byte, aper.DecodeState) (ERABInformationList, error) {
	return &v.decode
}
func BridgeERABInformationListValueCodecFieldEncode(v *ERABInformationListValueCodec) *func(ERABInformationList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListValueCodecFieldPath(v *ERABInformationListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListValueCodecMethodEncodeBudgetValue(v ERABInformationListValueCodec, a0 ERABInformationList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListValueCodecMethodEncodeChanged(v ERABInformationListValueCodec, a0 ERABInformationList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBindingFieldCodec(v *ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) *ERABToBeSetupItemBearerSUReqValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBindingFieldGet(v *ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) *func(*ERABToBeSetupItemBearerSUReqIEValue) (*ERABToBeSetupItemBearerSUReq, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBindingFieldInfo(v *ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBindingFieldInject(v *ERABToBeSetupItemBearerSUReqERABToBeSetupItemBearerSUReqIEBinding) *func(ERABToBeSetupItemBearerSUReq) ERABToBeSetupItemBearerSUReqIEValue {
	return &v.inject
}
func BridgeERABToBeSetupItemBearerSUReqExtIETableMethodInfoBearerType(v ERABToBeSetupItemBearerSUReqExtIETable) s00.ExtensionInfo {
	return v.infoBearerType()
}
func BridgeERABToBeSetupItemBearerSUReqExtIETableMethodInfoCorrelationID(v ERABToBeSetupItemBearerSUReqExtIETable) s00.ExtensionInfo {
	return v.infoCorrelationID()
}
func BridgeERABToBeSetupItemBearerSUReqExtIETableMethodInfoEthernetType(v ERABToBeSetupItemBearerSUReqExtIETable) s00.ExtensionInfo {
	return v.infoEthernetType()
}
func BridgeERABToBeSetupItemBearerSUReqExtIETableMethodInfoSIPTOCorrelationID(v ERABToBeSetupItemBearerSUReqExtIETable) s00.ExtensionInfo {
	return v.infoSIPTOCorrelationID()
}
func BridgeERABToBeSetupItemBearerSUReqExtIETableMethodInfoSecurityIndication(v ERABToBeSetupItemBearerSUReqExtIETable) s00.ExtensionInfo {
	return v.infoSecurityIndication()
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBindingFieldCodec(v *ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) *SecurityIndicationValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBindingFieldGet(v *ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) *func(*s28.ERABToBeSetupItemBearerSUReqExtIEsValue) (*s28.SecurityIndication, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBindingFieldInfo(v *ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBindingFieldInject(v *ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) *func(s28.SecurityIndication) s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemBearerSUReqFieldExtCount(v *ERABToBeSetupItemBearerSUReq) *int64 {
	return &v.extCount
}
func BridgeERABToBeSetupItemBearerSUReqFieldExtData(v *ERABToBeSetupItemBearerSUReq) *[][]byte {
	return &v.extData
}
func BridgeERABToBeSetupItemBearerSUReqFieldExtOrigin(v *ERABToBeSetupItemBearerSUReq) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABToBeSetupItemBearerSUReqFieldExtPresent(v *ERABToBeSetupItemBearerSUReq) *[]bool {
	return &v.extPresent
}
func BridgeERABToBeSetupItemBearerSUReqFieldExtWire(v *ERABToBeSetupItemBearerSUReq) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABToBeSetupItemBearerSUReqFieldIEExtensionsIndef(v *ERABToBeSetupItemBearerSUReq) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABToBeSetupItemBearerSUReqFieldPerExtPadding(v *ERABToBeSetupItemBearerSUReq) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABToBeSetupItemBearerSUReqFieldPerPadding(v *ERABToBeSetupItemBearerSUReq) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABToBeSetupItemBearerSUReqFieldReceived(v *ERABToBeSetupItemBearerSUReq) *bool {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqFieldReceivedAbsolute(v *ERABToBeSetupItemBearerSUReq) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSetupItemBearerSUReqFieldReceivedBytes(v *ERABToBeSetupItemBearerSUReq) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSetupItemBearerSUReqFieldReceivedLocation(v *ERABToBeSetupItemBearerSUReq) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSetupItemBearerSUReqFieldReplay(v *ERABToBeSetupItemBearerSUReq) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqFieldStream(v *ERABToBeSetupItemBearerSUReq) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemBearerSUReqFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReq) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqIEContainerValueCodec) *func(ERABToBeSetupItemBearerSUReqIEContainer, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqIEContainerValueCodec) *func(ERABToBeSetupItemBearerSUReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqIEContainerValueCodec) *func(ERABToBeSetupItemBearerSUReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqIEContainerValueCodec, a0 ERABToBeSetupItemBearerSUReqIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqIEContainerValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqIEContainerValueCodec, a0 ERABToBeSetupItemBearerSUReqIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldFieldReceived(v *ERABToBeSetupItemBearerSUReqIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldFieldReplay(v *ERABToBeSetupItemBearerSUReqIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldFieldStream(v *ERABToBeSetupItemBearerSUReqIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldMethodMarshalAPERTo(v *ERABToBeSetupItemBearerSUReqIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemBearerSUReqIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqIEFieldValueCodec) *func(ERABToBeSetupItemBearerSUReqIEField, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqIEFieldValueCodec) *func(ERABToBeSetupItemBearerSUReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEField, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqIEFieldValueCodec) *func(ERABToBeSetupItemBearerSUReqIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqIEFieldValueCodec, a0 ERABToBeSetupItemBearerSUReqIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqIEFieldValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqIEFieldValueCodec, a0 ERABToBeSetupItemBearerSUReqIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqIETableMethodInfoERABToBeSetupItemBearerSUReq(v ERABToBeSetupItemBearerSUReqIETable) s00.FieldInfo {
	return v.infoERABToBeSetupItemBearerSUReq()
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec, a0 ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListValueCodec, a0 ERABToBeSetupItemBearerSUReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueFieldId(v *ERABToBeSetupItemBearerSUReqIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemBearerSUReqIEValueFieldIsOpaque(v *ERABToBeSetupItemBearerSUReqIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemBearerSUReqIEValueFieldOpaque(v *ERABToBeSetupItemBearerSUReqIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemBearerSUReqIEValueFieldReceived(v *ERABToBeSetupItemBearerSUReqIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqIEValueFieldReplay(v *ERABToBeSetupItemBearerSUReqIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqIEValueFieldRowERABToBeSetupItemBearerSUReq(v *ERABToBeSetupItemBearerSUReqIEValue) **ERABToBeSetupItemBearerSUReq {
	return &v.rowERABToBeSetupItemBearerSUReq
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodCaptureSemantics(v ERABToBeSetupItemBearerSUReqIEValue, a0 aper.SemanticCapture) ERABToBeSetupItemBearerSUReqIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodCompareSemantics(v ERABToBeSetupItemBearerSUReqIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodDecode(v ERABToBeSetupItemBearerSUReqIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSetupItemBearerSUReqIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodEncode(v ERABToBeSetupItemBearerSUReqIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodEncodeFresh(v ERABToBeSetupItemBearerSUReqIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodMatchesID(v ERABToBeSetupItemBearerSUReqIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodReason(v ERABToBeSetupItemBearerSUReqIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueMethodRule(v ERABToBeSetupItemBearerSUReqIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERBudget(v *ERABToBeSetupItemBearerSUReq, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERBudgetValue(v *ERABToBeSetupItemBearerSUReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERChanged(v *ERABToBeSetupItemBearerSUReq, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERChangedValue(v *ERABToBeSetupItemBearerSUReq, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERLegacy(v *ERABToBeSetupItemBearerSUReq) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERNewValue(v *ERABToBeSetupItemBearerSUReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERPlanned(v *ERABToBeSetupItemBearerSUReq, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERTo(v *ERABToBeSetupItemBearerSUReq, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemBearerSUReqMethodUnmarshalAPERFrom(v *ERABToBeSetupItemBearerSUReq, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemBearerSUReqMethodUnmarshalAPERLegacy(v *ERABToBeSetupItemBearerSUReq, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSetupItemBearerSUReqMethodUnmarshalAPERWithOptions(v *ERABToBeSetupItemBearerSUReq, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqValueCodec) *func(ERABToBeSetupItemBearerSUReq, aper.DecodeState) (ERABToBeSetupItemBearerSUReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqValueCodec) *func(ERABToBeSetupItemBearerSUReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReq, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqValueCodec) *func(ERABToBeSetupItemBearerSUReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqValueCodec, a0 ERABToBeSetupItemBearerSUReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqValueCodec, a0 ERABToBeSetupItemBearerSUReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBindingFieldCodec(v *ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) *ERABToBeSetupItemCtxtSUReqValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBindingFieldGet(v *ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) *func(*ERABToBeSetupItemCtxtSUReqIEValue) (*ERABToBeSetupItemCtxtSUReq, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBindingFieldInfo(v *ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBindingFieldInject(v *ERABToBeSetupItemCtxtSUReqERABToBeSetupItemCtxtSUReqIEBinding) *func(ERABToBeSetupItemCtxtSUReq) ERABToBeSetupItemCtxtSUReqIEValue {
	return &v.inject
}
func BridgeERABToBeSetupItemCtxtSUReqExtIETableMethodInfoBearerType(v ERABToBeSetupItemCtxtSUReqExtIETable) s00.ExtensionInfo {
	return v.infoBearerType()
}
func BridgeERABToBeSetupItemCtxtSUReqExtIETableMethodInfoCorrelationID(v ERABToBeSetupItemCtxtSUReqExtIETable) s00.ExtensionInfo {
	return v.infoCorrelationID()
}
func BridgeERABToBeSetupItemCtxtSUReqExtIETableMethodInfoEthernetType(v ERABToBeSetupItemCtxtSUReqExtIETable) s00.ExtensionInfo {
	return v.infoEthernetType()
}
func BridgeERABToBeSetupItemCtxtSUReqExtIETableMethodInfoSIPTOCorrelationID(v ERABToBeSetupItemCtxtSUReqExtIETable) s00.ExtensionInfo {
	return v.infoSIPTOCorrelationID()
}
func BridgeERABToBeSetupItemCtxtSUReqExtIETableMethodInfoSecurityIndication(v ERABToBeSetupItemCtxtSUReqExtIETable) s00.ExtensionInfo {
	return v.infoSecurityIndication()
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBindingFieldCodec(v *ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) *SecurityIndicationValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBindingFieldGet(v *ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) *func(*s28.ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s28.SecurityIndication, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBindingFieldInfo(v *ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBindingFieldInject(v *ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) *func(s28.SecurityIndication) s28.ERABToBeSetupItemCtxtSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemCtxtSUReqFieldExtCount(v *ERABToBeSetupItemCtxtSUReq) *int64 {
	return &v.extCount
}
func BridgeERABToBeSetupItemCtxtSUReqFieldExtData(v *ERABToBeSetupItemCtxtSUReq) *[][]byte {
	return &v.extData
}
func BridgeERABToBeSetupItemCtxtSUReqFieldExtOrigin(v *ERABToBeSetupItemCtxtSUReq) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABToBeSetupItemCtxtSUReqFieldExtPresent(v *ERABToBeSetupItemCtxtSUReq) *[]bool {
	return &v.extPresent
}
func BridgeERABToBeSetupItemCtxtSUReqFieldExtWire(v *ERABToBeSetupItemCtxtSUReq) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABToBeSetupItemCtxtSUReqFieldIEExtensionsIndef(v *ERABToBeSetupItemCtxtSUReq) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABToBeSetupItemCtxtSUReqFieldPerExtPadding(v *ERABToBeSetupItemCtxtSUReq) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABToBeSetupItemCtxtSUReqFieldPerPadding(v *ERABToBeSetupItemCtxtSUReq) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABToBeSetupItemCtxtSUReqFieldReceived(v *ERABToBeSetupItemCtxtSUReq) *bool {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqFieldReceivedAbsolute(v *ERABToBeSetupItemCtxtSUReq) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSetupItemCtxtSUReqFieldReceivedBytes(v *ERABToBeSetupItemCtxtSUReq) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSetupItemCtxtSUReqFieldReceivedLocation(v *ERABToBeSetupItemCtxtSUReq) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSetupItemCtxtSUReqFieldReplay(v *ERABToBeSetupItemCtxtSUReq) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqFieldStream(v *ERABToBeSetupItemCtxtSUReq) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemCtxtSUReqFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReq) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEContainer, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqIEContainerValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqIEContainerValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqIEContainerValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldFieldReceived(v *ERABToBeSetupItemCtxtSUReqIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldFieldReplay(v *ERABToBeSetupItemCtxtSUReqIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldFieldStream(v *ERABToBeSetupItemCtxtSUReqIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldMethodMarshalAPERTo(v *ERABToBeSetupItemCtxtSUReqIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemCtxtSUReqIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEField, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEField, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqIEFieldValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqIEFieldValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqIEFieldValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqIETableMethodInfoERABToBeSetupItemCtxtSUReq(v ERABToBeSetupItemCtxtSUReqIETable) s00.FieldInfo {
	return v.infoERABToBeSetupItemCtxtSUReq()
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueFieldId(v *ERABToBeSetupItemCtxtSUReqIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueFieldIsOpaque(v *ERABToBeSetupItemCtxtSUReqIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueFieldOpaque(v *ERABToBeSetupItemCtxtSUReqIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueFieldRowERABToBeSetupItemCtxtSUReq(v *ERABToBeSetupItemCtxtSUReqIEValue) **ERABToBeSetupItemCtxtSUReq {
	return &v.rowERABToBeSetupItemCtxtSUReq
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodCaptureSemantics(v ERABToBeSetupItemCtxtSUReqIEValue, a0 aper.SemanticCapture) ERABToBeSetupItemCtxtSUReqIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodCompareSemantics(v ERABToBeSetupItemCtxtSUReqIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodDecode(v ERABToBeSetupItemCtxtSUReqIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSetupItemCtxtSUReqIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodEncode(v ERABToBeSetupItemCtxtSUReqIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodEncodeFresh(v ERABToBeSetupItemCtxtSUReqIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodMatchesID(v ERABToBeSetupItemCtxtSUReqIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodReason(v ERABToBeSetupItemCtxtSUReqIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueMethodRule(v ERABToBeSetupItemCtxtSUReqIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERBudget(v *ERABToBeSetupItemCtxtSUReq, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERBudgetValue(v *ERABToBeSetupItemCtxtSUReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERChanged(v *ERABToBeSetupItemCtxtSUReq, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERChangedValue(v *ERABToBeSetupItemCtxtSUReq, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERLegacy(v *ERABToBeSetupItemCtxtSUReq) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERNewValue(v *ERABToBeSetupItemCtxtSUReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERPlanned(v *ERABToBeSetupItemCtxtSUReq, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodMarshalAPERTo(v *ERABToBeSetupItemCtxtSUReq, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodUnmarshalAPERFrom(v *ERABToBeSetupItemCtxtSUReq, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodUnmarshalAPERLegacy(v *ERABToBeSetupItemCtxtSUReq, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqMethodUnmarshalAPERWithOptions(v *ERABToBeSetupItemCtxtSUReq, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqValueCodec) *func(ERABToBeSetupItemCtxtSUReq, aper.DecodeState) (ERABToBeSetupItemCtxtSUReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqValueCodec) *func(ERABToBeSetupItemCtxtSUReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReq, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqValueCodec) *func(ERABToBeSetupItemCtxtSUReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqValueCodec, a0 ERABToBeSetupItemCtxtSUReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqValueCodec, a0 ERABToBeSetupItemCtxtSUReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqAPERValueFieldContext(v *ERABToBeSetupItemHOReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqAPERValueFieldReceived(v *ERABToBeSetupItemHOReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqAPERValueFieldReplay(v *ERABToBeSetupItemHOReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBindingFieldCodec(v *ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) *ERABToBeSetupItemHOReqValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBindingFieldGet(v *ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) *func(*ERABToBeSetupItemHOReqIEValue) (*ERABToBeSetupItemHOReq, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBindingFieldInfo(v *ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBindingFieldInject(v *ERABToBeSetupItemHOReqERABToBeSetupItemHOReqIEBinding) *func(ERABToBeSetupItemHOReq) ERABToBeSetupItemHOReqIEValue {
	return &v.inject
}
func BridgeERABToBeSetupItemHOReqExtIETableMethodInfoBearerType(v ERABToBeSetupItemHOReqExtIETable) s00.ExtensionInfo {
	return v.infoBearerType()
}
func BridgeERABToBeSetupItemHOReqExtIETableMethodInfoDataForwardingNotPossible(v ERABToBeSetupItemHOReqExtIETable) s00.ExtensionInfo {
	return v.infoDataForwardingNotPossible()
}
func BridgeERABToBeSetupItemHOReqExtIETableMethodInfoEthernetType(v ERABToBeSetupItemHOReqExtIETable) s00.ExtensionInfo {
	return v.infoEthernetType()
}
func BridgeERABToBeSetupItemHOReqExtIETableMethodInfoSecurityIndication(v ERABToBeSetupItemHOReqExtIETable) s00.ExtensionInfo {
	return v.infoSecurityIndication()
}
func BridgeERABToBeSetupItemHOReqExtIEsBearerTypeExtBindingFieldCodec(v *ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) *s00.BearerTypeValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemHOReqExtIEsBearerTypeExtBindingFieldGet(v *ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) *func(*ERABToBeSetupItemHOReqExtIEsValue) (*s00.BearerType, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemHOReqExtIEsBearerTypeExtBindingFieldInfo(v *ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemHOReqExtIEsBearerTypeExtBindingFieldInject(v *ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding) *func(s00.BearerType) ERABToBeSetupItemHOReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBindingFieldCodec(v *ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) *s00.DataForwardingNotPossibleValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBindingFieldGet(v *ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) *func(*ERABToBeSetupItemHOReqExtIEsValue) (*s00.DataForwardingNotPossible, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBindingFieldInfo(v *ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBindingFieldInject(v *ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding) *func(s00.DataForwardingNotPossible) ERABToBeSetupItemHOReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemHOReqExtIEsEthernetTypeExtBindingFieldCodec(v *ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) *s00.EthernetTypeValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemHOReqExtIEsEthernetTypeExtBindingFieldGet(v *ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) *func(*ERABToBeSetupItemHOReqExtIEsValue) (*s00.EthernetType, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemHOReqExtIEsEthernetTypeExtBindingFieldInfo(v *ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemHOReqExtIEsEthernetTypeExtBindingFieldInject(v *ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding) *func(s00.EthernetType) ERABToBeSetupItemHOReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerAPERValueFieldContext(v *ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerAPERValueFieldReceived(v *ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerAPERValueFieldReplay(v *ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemHOReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemHOReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecFieldContext(v *ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemHOReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecFieldPath(v *ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec, a0 ERABToBeSetupItemHOReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqExtIEsExtContainerValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec, a0 ERABToBeSetupItemHOReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldAPERValueFieldContext(v *ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldAPERValueFieldReceived(v *ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldAPERValueFieldReplay(v *ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldFieldReceived(v *ERABToBeSetupItemHOReqExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldFieldReplay(v *ERABToBeSetupItemHOReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldFieldStream(v *ERABToBeSetupItemHOReqExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldFieldWithoutReplay(v *ERABToBeSetupItemHOReqExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeSetupItemHOReqExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemHOReqExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemHOReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemHOReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecFieldContext(v *ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemHOReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecFieldPath(v *ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec, a0 ERABToBeSetupItemHOReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec, a0 ERABToBeSetupItemHOReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqExtIEsIEFieldFieldReceived(v *ERABToBeSetupItemHOReqExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqExtIEsIEFieldFieldReplay(v *ERABToBeSetupItemHOReqExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqExtIEsIEFieldFieldStream(v *ERABToBeSetupItemHOReqExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemHOReqExtIEsIEFieldFieldWithoutReplay(v *ERABToBeSetupItemHOReqExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqExtIEsIEFieldMethodMarshalAPERTo(v *ERABToBeSetupItemHOReqExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemHOReqExtIEsIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemHOReqExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBindingFieldCodec(v *ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) *SecurityIndicationValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBindingFieldGet(v *ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) *func(*ERABToBeSetupItemHOReqExtIEsValue) (*s28.SecurityIndication, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBindingFieldInfo(v *ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBindingFieldInject(v *ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) *func(s28.SecurityIndication) ERABToBeSetupItemHOReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(v *ERABToBeSetupItemHOReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldIsOpaque(v *ERABToBeSetupItemHOReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldOpaque(v *ERABToBeSetupItemHOReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldReceived(v *ERABToBeSetupItemHOReqExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldReplay(v *ERABToBeSetupItemHOReqExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowBearerType(v *ERABToBeSetupItemHOReqExtIEsValue) **s00.BearerType {
	return &v.rowBearerType
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowDataForwardingNotPossible(v *ERABToBeSetupItemHOReqExtIEsValue) **s00.DataForwardingNotPossible {
	return &v.rowDataForwardingNotPossible
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowEthernetType(v *ERABToBeSetupItemHOReqExtIEsValue) **s00.EthernetType {
	return &v.rowEthernetType
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowSecurityIndication(v *ERABToBeSetupItemHOReqExtIEsValue) **s28.SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodCaptureSemantics(v ERABToBeSetupItemHOReqExtIEsValue, a0 aper.SemanticCapture) ERABToBeSetupItemHOReqExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodCompareSemantics(v ERABToBeSetupItemHOReqExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodDecode(v ERABToBeSetupItemHOReqExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSetupItemHOReqExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodEncode(v ERABToBeSetupItemHOReqExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodEncodeFresh(v ERABToBeSetupItemHOReqExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodMatchesID(v ERABToBeSetupItemHOReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodReason(v ERABToBeSetupItemHOReqExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodRule(v ERABToBeSetupItemHOReqExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSetupItemHOReqFieldExtCount(v *ERABToBeSetupItemHOReq) *int64   { return &v.extCount }
func BridgeERABToBeSetupItemHOReqFieldExtData(v *ERABToBeSetupItemHOReq) *[][]byte { return &v.extData }
func BridgeERABToBeSetupItemHOReqFieldExtOrigin(v *ERABToBeSetupItemHOReq) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABToBeSetupItemHOReqFieldExtPresent(v *ERABToBeSetupItemHOReq) *[]bool {
	return &v.extPresent
}
func BridgeERABToBeSetupItemHOReqFieldExtWire(v *ERABToBeSetupItemHOReq) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABToBeSetupItemHOReqFieldIEExtensionsIndef(v *ERABToBeSetupItemHOReq) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABToBeSetupItemHOReqFieldPerExtPadding(v *ERABToBeSetupItemHOReq) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABToBeSetupItemHOReqFieldPerPadding(v *ERABToBeSetupItemHOReq) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABToBeSetupItemHOReqFieldReceived(v *ERABToBeSetupItemHOReq) *bool { return &v.received }
func BridgeERABToBeSetupItemHOReqFieldReceivedAbsolute(v *ERABToBeSetupItemHOReq) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSetupItemHOReqFieldReceivedBytes(v *ERABToBeSetupItemHOReq) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSetupItemHOReqFieldReceivedLocation(v *ERABToBeSetupItemHOReq) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSetupItemHOReqFieldReplay(v *ERABToBeSetupItemHOReq) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqFieldStream(v *ERABToBeSetupItemHOReq) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemHOReqFieldWithoutReplay(v *ERABToBeSetupItemHOReq) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqIEContainerAPERValueFieldContext(v *ERABToBeSetupItemHOReqIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEContainerAPERValueFieldReceived(v *ERABToBeSetupItemHOReqIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqIEContainerAPERValueFieldReplay(v *ERABToBeSetupItemHOReqIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqIEContainerAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldCapture(v *ERABToBeSetupItemHOReqIEContainerValueCodec) *func(ERABToBeSetupItemHOReqIEContainer, aper.DecodeState) (ERABToBeSetupItemHOReqIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldCompare(v *ERABToBeSetupItemHOReqIEContainerValueCodec) *func(ERABToBeSetupItemHOReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldContext(v *ERABToBeSetupItemHOReqIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldDecode(v *ERABToBeSetupItemHOReqIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldEncode(v *ERABToBeSetupItemHOReqIEContainerValueCodec) *func(ERABToBeSetupItemHOReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecFieldPath(v *ERABToBeSetupItemHOReqIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqIEContainerValueCodec, a0 ERABToBeSetupItemHOReqIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqIEContainerValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqIEContainerValueCodec, a0 ERABToBeSetupItemHOReqIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqIEFieldAPERValueFieldContext(v *ERABToBeSetupItemHOReqIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEFieldAPERValueFieldReceived(v *ERABToBeSetupItemHOReqIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqIEFieldAPERValueFieldReplay(v *ERABToBeSetupItemHOReqIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqIEFieldAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqIEFieldFieldReceived(v *ERABToBeSetupItemHOReqIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqIEFieldFieldReplay(v *ERABToBeSetupItemHOReqIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqIEFieldFieldStream(v *ERABToBeSetupItemHOReqIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemHOReqIEFieldFieldWithoutReplay(v *ERABToBeSetupItemHOReqIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqIEFieldMethodMarshalAPERTo(v *ERABToBeSetupItemHOReqIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemHOReqIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemHOReqIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldCapture(v *ERABToBeSetupItemHOReqIEFieldValueCodec) *func(ERABToBeSetupItemHOReqIEField, aper.DecodeState) (ERABToBeSetupItemHOReqIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldCompare(v *ERABToBeSetupItemHOReqIEFieldValueCodec) *func(ERABToBeSetupItemHOReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldContext(v *ERABToBeSetupItemHOReqIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldDecode(v *ERABToBeSetupItemHOReqIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEField, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldEncode(v *ERABToBeSetupItemHOReqIEFieldValueCodec) *func(ERABToBeSetupItemHOReqIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecFieldPath(v *ERABToBeSetupItemHOReqIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqIEFieldValueCodec, a0 ERABToBeSetupItemHOReqIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqIEFieldValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqIEFieldValueCodec, a0 ERABToBeSetupItemHOReqIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec, a0 ERABToBeSetupItemHOReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqIEValueERABIEContainerListValueCodec, a0 ERABToBeSetupItemHOReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqIEValueFieldId(v *ERABToBeSetupItemHOReqIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemHOReqIEValueFieldIsOpaque(v *ERABToBeSetupItemHOReqIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemHOReqIEValueFieldOpaque(v *ERABToBeSetupItemHOReqIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemHOReqIEValueFieldReceived(v *ERABToBeSetupItemHOReqIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqIEValueFieldReplay(v *ERABToBeSetupItemHOReqIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqIEValueFieldRowERABToBeSetupItemHOReq(v *ERABToBeSetupItemHOReqIEValue) **ERABToBeSetupItemHOReq {
	return &v.rowERABToBeSetupItemHOReq
}
func BridgeERABToBeSetupItemHOReqIEValueMethodCaptureSemantics(v ERABToBeSetupItemHOReqIEValue, a0 aper.SemanticCapture) ERABToBeSetupItemHOReqIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemHOReqIEValueMethodCompareSemantics(v ERABToBeSetupItemHOReqIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemHOReqIEValueMethodDecode(v ERABToBeSetupItemHOReqIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSetupItemHOReqIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSetupItemHOReqIEValueMethodEncode(v ERABToBeSetupItemHOReqIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSetupItemHOReqIEValueMethodEncodeFresh(v ERABToBeSetupItemHOReqIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSetupItemHOReqIEValueMethodMatchesID(v ERABToBeSetupItemHOReqIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemHOReqIEValueMethodReason(v ERABToBeSetupItemHOReqIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSetupItemHOReqIEValueMethodRule(v ERABToBeSetupItemHOReqIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqIEValueProtocolIEContainerListValueCodec, a0 ERABToBeSetupItemHOReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERBudget(v *ERABToBeSetupItemHOReq, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERBudgetValue(v *ERABToBeSetupItemHOReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERChanged(v *ERABToBeSetupItemHOReq, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERChangedValue(v *ERABToBeSetupItemHOReq, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERLegacy(v *ERABToBeSetupItemHOReq) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERNewValue(v *ERABToBeSetupItemHOReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERPlanned(v *ERABToBeSetupItemHOReq, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqMethodMarshalAPERTo(v *ERABToBeSetupItemHOReq, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemHOReqMethodUnmarshalAPERFrom(v *ERABToBeSetupItemHOReq, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemHOReqMethodUnmarshalAPERLegacy(v *ERABToBeSetupItemHOReq, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSetupItemHOReqMethodUnmarshalAPERWithOptions(v *ERABToBeSetupItemHOReq, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSetupItemHOReqValueCodecFieldCapture(v *ERABToBeSetupItemHOReqValueCodec) *func(ERABToBeSetupItemHOReq, aper.DecodeState) (ERABToBeSetupItemHOReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemHOReqValueCodecFieldCompare(v *ERABToBeSetupItemHOReqValueCodec) *func(ERABToBeSetupItemHOReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemHOReqValueCodecFieldContext(v *ERABToBeSetupItemHOReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemHOReqValueCodecFieldDecode(v *ERABToBeSetupItemHOReqValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemHOReq, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemHOReqValueCodecFieldEncode(v *ERABToBeSetupItemHOReqValueCodec) *func(ERABToBeSetupItemHOReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemHOReqValueCodecFieldPath(v *ERABToBeSetupItemHOReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemHOReqValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemHOReqValueCodec, a0 ERABToBeSetupItemHOReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemHOReqValueCodecMethodEncodeChanged(v ERABToBeSetupItemHOReqValueCodec, a0 ERABToBeSetupItemHOReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupListBearerSUReqAPERValueFieldContext(v *ERABToBeSetupListBearerSUReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupListBearerSUReqAPERValueFieldReceived(v *ERABToBeSetupListBearerSUReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupListBearerSUReqAPERValueFieldReplay(v *ERABToBeSetupListBearerSUReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupListBearerSUReqAPERValueFieldWithoutReplay(v *ERABToBeSetupListBearerSUReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupListBearerSUReqValueCodecFieldCapture(v *ERABToBeSetupListBearerSUReqValueCodec) *func(ERABToBeSetupListBearerSUReq, aper.DecodeState) (ERABToBeSetupListBearerSUReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupListBearerSUReqValueCodecFieldCompare(v *ERABToBeSetupListBearerSUReqValueCodec) *func(ERABToBeSetupListBearerSUReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupListBearerSUReqValueCodecFieldContext(v *ERABToBeSetupListBearerSUReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupListBearerSUReqValueCodecFieldDecode(v *ERABToBeSetupListBearerSUReqValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupListBearerSUReq, error) {
	return &v.decode
}
func BridgeERABToBeSetupListBearerSUReqValueCodecFieldEncode(v *ERABToBeSetupListBearerSUReqValueCodec) *func(ERABToBeSetupListBearerSUReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupListBearerSUReqValueCodecFieldPath(v *ERABToBeSetupListBearerSUReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupListBearerSUReqValueCodecMethodEncodeBudgetValue(v ERABToBeSetupListBearerSUReqValueCodec, a0 ERABToBeSetupListBearerSUReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupListBearerSUReqValueCodecMethodEncodeChanged(v ERABToBeSetupListBearerSUReqValueCodec, a0 ERABToBeSetupListBearerSUReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupListCtxtSUReqAPERValueFieldContext(v *ERABToBeSetupListCtxtSUReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupListCtxtSUReqAPERValueFieldReceived(v *ERABToBeSetupListCtxtSUReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupListCtxtSUReqAPERValueFieldReplay(v *ERABToBeSetupListCtxtSUReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupListCtxtSUReqAPERValueFieldWithoutReplay(v *ERABToBeSetupListCtxtSUReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecFieldCapture(v *ERABToBeSetupListCtxtSUReqValueCodec) *func(ERABToBeSetupListCtxtSUReq, aper.DecodeState) (ERABToBeSetupListCtxtSUReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecFieldCompare(v *ERABToBeSetupListCtxtSUReqValueCodec) *func(ERABToBeSetupListCtxtSUReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecFieldContext(v *ERABToBeSetupListCtxtSUReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecFieldDecode(v *ERABToBeSetupListCtxtSUReqValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupListCtxtSUReq, error) {
	return &v.decode
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecFieldEncode(v *ERABToBeSetupListCtxtSUReqValueCodec) *func(ERABToBeSetupListCtxtSUReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecFieldPath(v *ERABToBeSetupListCtxtSUReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecMethodEncodeBudgetValue(v ERABToBeSetupListCtxtSUReqValueCodec, a0 ERABToBeSetupListCtxtSUReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupListCtxtSUReqValueCodecMethodEncodeChanged(v ERABToBeSetupListCtxtSUReqValueCodec, a0 ERABToBeSetupListCtxtSUReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemExtIETableMethodInfoSecurityIndication(v ERABToBeSwitchedDLItemExtIETable) s00.ExtensionInfo {
	return v.infoSecurityIndication()
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerAPERValueFieldContext(v *ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerAPERValueFieldReceived(v *ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerAPERValueFieldReplay(v *ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) *func(ERABToBeSwitchedDLItemExtIEsExtContainer, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) *func(ERABToBeSwitchedDLItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldContext(v *ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) *func(ERABToBeSwitchedDLItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecFieldPath(v *ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec, a0 ERABToBeSwitchedDLItemExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemExtIEsExtContainerValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec, a0 ERABToBeSwitchedDLItemExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldAPERValueFieldContext(v *ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldAPERValueFieldReceived(v *ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldAPERValueFieldReplay(v *ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldAPERValueFieldWithoutReplay(v *ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldReceived(v *ERABToBeSwitchedDLItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldReplay(v *ERABToBeSwitchedDLItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldStream(v *ERABToBeSwitchedDLItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldWithoutReplay(v *ERABToBeSwitchedDLItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeSwitchedDLItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeSwitchedDLItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) *func(ERABToBeSwitchedDLItemExtIEsExtField, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) *func(ERABToBeSwitchedDLItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldContext(v *ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedDLItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) *func(ERABToBeSwitchedDLItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecFieldPath(v *ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec, a0 ERABToBeSwitchedDLItemExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldValueCodecMethodEncodeChanged(v ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec, a0 ERABToBeSwitchedDLItemExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSwitchedDLItemExtIEsIEFieldFieldReceived(v *ERABToBeSwitchedDLItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemExtIEsIEFieldFieldReplay(v *ERABToBeSwitchedDLItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemExtIEsIEFieldFieldStream(v *ERABToBeSwitchedDLItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSwitchedDLItemExtIEsIEFieldFieldWithoutReplay(v *ERABToBeSwitchedDLItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLItemExtIEsIEFieldMethodMarshalAPERTo(v *ERABToBeSwitchedDLItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSwitchedDLItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSwitchedDLItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBindingFieldCodec(v *ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) *SecurityIndicationValueCodec {
	return &v.codec
}
func BridgeERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBindingFieldGet(v *ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) *func(*ERABToBeSwitchedDLItemExtIEsValue) (*s28.SecurityIndication, bool) {
	return &v.get
}
func BridgeERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBindingFieldInfo(v *ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBindingFieldInject(v *ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) *func(s28.SecurityIndication) ERABToBeSwitchedDLItemExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldId(v *ERABToBeSwitchedDLItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldIsOpaque(v *ERABToBeSwitchedDLItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldOpaque(v *ERABToBeSwitchedDLItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldReceived(v *ERABToBeSwitchedDLItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldReplay(v *ERABToBeSwitchedDLItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldRowSecurityIndication(v *ERABToBeSwitchedDLItemExtIEsValue) **s28.SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodCaptureSemantics(v ERABToBeSwitchedDLItemExtIEsValue, a0 aper.SemanticCapture) ERABToBeSwitchedDLItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodCompareSemantics(v ERABToBeSwitchedDLItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodDecode(v ERABToBeSwitchedDLItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSwitchedDLItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodEncode(v ERABToBeSwitchedDLItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodEncodeFresh(v ERABToBeSwitchedDLItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodMatchesID(v ERABToBeSwitchedDLItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodReason(v ERABToBeSwitchedDLItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodRule(v ERABToBeSwitchedDLItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeUpdatedItemAPERValueFieldContext(v *ERABToBeUpdatedItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemAPERValueFieldReceived(v *ERABToBeUpdatedItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedItemAPERValueFieldReplay(v *ERABToBeUpdatedItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemAPERValueFieldWithoutReplay(v *ERABToBeUpdatedItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemERABToBeUpdatedItemIEBindingFieldCodec(v *ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) *ERABToBeUpdatedItemValueCodec {
	return &v.codec
}
func BridgeERABToBeUpdatedItemERABToBeUpdatedItemIEBindingFieldGet(v *ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) *func(*ERABToBeUpdatedItemIEValue) (*ERABToBeUpdatedItem, bool) {
	return &v.get
}
func BridgeERABToBeUpdatedItemERABToBeUpdatedItemIEBindingFieldInfo(v *ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABToBeUpdatedItemERABToBeUpdatedItemIEBindingFieldInject(v *ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding) *func(ERABToBeUpdatedItem) ERABToBeUpdatedItemIEValue {
	return &v.inject
}
func BridgeERABToBeUpdatedItemFieldExtCount(v *ERABToBeUpdatedItem) *int64   { return &v.extCount }
func BridgeERABToBeUpdatedItemFieldExtData(v *ERABToBeUpdatedItem) *[][]byte { return &v.extData }
func BridgeERABToBeUpdatedItemFieldExtOrigin(v *ERABToBeUpdatedItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABToBeUpdatedItemFieldExtPresent(v *ERABToBeUpdatedItem) *[]bool { return &v.extPresent }
func BridgeERABToBeUpdatedItemFieldExtWire(v *ERABToBeUpdatedItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABToBeUpdatedItemFieldIEExtensionsIndef(v *ERABToBeUpdatedItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABToBeUpdatedItemFieldPerExtPadding(v *ERABToBeUpdatedItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABToBeUpdatedItemFieldPerPadding(v *ERABToBeUpdatedItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABToBeUpdatedItemFieldReceived(v *ERABToBeUpdatedItem) *bool { return &v.received }
func BridgeERABToBeUpdatedItemFieldReceivedAbsolute(v *ERABToBeUpdatedItem) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeUpdatedItemFieldReceivedBytes(v *ERABToBeUpdatedItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeUpdatedItemFieldReceivedLocation(v *ERABToBeUpdatedItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeUpdatedItemFieldReplay(v *ERABToBeUpdatedItem) *aper.Snapshot { return &v.replay }
func BridgeERABToBeUpdatedItemFieldStream(v *ERABToBeUpdatedItem) *aper.WireSpan { return &v.stream }
func BridgeERABToBeUpdatedItemFieldWithoutReplay(v *ERABToBeUpdatedItem) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemIEContainerAPERValueFieldContext(v *ERABToBeUpdatedItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEContainerAPERValueFieldReceived(v *ERABToBeUpdatedItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedItemIEContainerAPERValueFieldReplay(v *ERABToBeUpdatedItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemIEContainerAPERValueFieldWithoutReplay(v *ERABToBeUpdatedItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecFieldCapture(v *ERABToBeUpdatedItemIEContainerValueCodec) *func(ERABToBeUpdatedItemIEContainer, aper.DecodeState) (ERABToBeUpdatedItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecFieldCompare(v *ERABToBeUpdatedItemIEContainerValueCodec) *func(ERABToBeUpdatedItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecFieldContext(v *ERABToBeUpdatedItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecFieldDecode(v *ERABToBeUpdatedItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecFieldEncode(v *ERABToBeUpdatedItemIEContainerValueCodec) *func(ERABToBeUpdatedItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecFieldPath(v *ERABToBeUpdatedItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecMethodEncodeBudgetValue(v ERABToBeUpdatedItemIEContainerValueCodec, a0 ERABToBeUpdatedItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemIEContainerValueCodecMethodEncodeChanged(v ERABToBeUpdatedItemIEContainerValueCodec, a0 ERABToBeUpdatedItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeUpdatedItemIEFieldAPERValueFieldContext(v *ERABToBeUpdatedItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEFieldAPERValueFieldReceived(v *ERABToBeUpdatedItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedItemIEFieldAPERValueFieldReplay(v *ERABToBeUpdatedItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemIEFieldAPERValueFieldWithoutReplay(v *ERABToBeUpdatedItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemIEFieldFieldReceived(v *ERABToBeUpdatedItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeUpdatedItemIEFieldFieldReplay(v *ERABToBeUpdatedItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemIEFieldFieldStream(v *ERABToBeUpdatedItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeUpdatedItemIEFieldFieldWithoutReplay(v *ERABToBeUpdatedItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemIEFieldMethodMarshalAPERTo(v *ERABToBeUpdatedItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeUpdatedItemIEFieldMethodUnmarshalAPERFrom(v *ERABToBeUpdatedItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecFieldCapture(v *ERABToBeUpdatedItemIEFieldValueCodec) *func(ERABToBeUpdatedItemIEField, aper.DecodeState) (ERABToBeUpdatedItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecFieldCompare(v *ERABToBeUpdatedItemIEFieldValueCodec) *func(ERABToBeUpdatedItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecFieldContext(v *ERABToBeUpdatedItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecFieldDecode(v *ERABToBeUpdatedItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEField, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecFieldEncode(v *ERABToBeUpdatedItemIEFieldValueCodec) *func(ERABToBeUpdatedItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecFieldPath(v *ERABToBeUpdatedItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecMethodEncodeBudgetValue(v ERABToBeUpdatedItemIEFieldValueCodec, a0 ERABToBeUpdatedItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemIEFieldValueCodecMethodEncodeChanged(v ERABToBeUpdatedItemIEFieldValueCodec, a0 ERABToBeUpdatedItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeUpdatedItemIETableMethodInfoERABToBeUpdatedItem(v ERABToBeUpdatedItemIETable) s00.FieldInfo {
	return v.infoERABToBeUpdatedItem()
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListAPERValueFieldContext(v *ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListAPERValueFieldReceived(v *ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListAPERValueFieldReplay(v *ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueERABIEContainerList, aper.DecodeState) (ERABToBeUpdatedItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec, a0 ERABToBeUpdatedItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec, a0 ERABToBeUpdatedItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeUpdatedItemIEValueFieldId(v *ERABToBeUpdatedItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeUpdatedItemIEValueFieldIsOpaque(v *ERABToBeUpdatedItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeUpdatedItemIEValueFieldOpaque(v *ERABToBeUpdatedItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeUpdatedItemIEValueFieldReceived(v *ERABToBeUpdatedItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedItemIEValueFieldReplay(v *ERABToBeUpdatedItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemIEValueFieldRowERABToBeUpdatedItem(v *ERABToBeUpdatedItemIEValue) **ERABToBeUpdatedItem {
	return &v.rowERABToBeUpdatedItem
}
func BridgeERABToBeUpdatedItemIEValueMethodCaptureSemantics(v ERABToBeUpdatedItemIEValue, a0 aper.SemanticCapture) ERABToBeUpdatedItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeUpdatedItemIEValueMethodCompareSemantics(v ERABToBeUpdatedItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeUpdatedItemIEValueMethodDecode(v ERABToBeUpdatedItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeUpdatedItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeUpdatedItemIEValueMethodEncode(v ERABToBeUpdatedItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeUpdatedItemIEValueMethodEncodeFresh(v ERABToBeUpdatedItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeUpdatedItemIEValueMethodMatchesID(v ERABToBeUpdatedItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeUpdatedItemIEValueMethodReason(v ERABToBeUpdatedItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeUpdatedItemIEValueMethodRule(v ERABToBeUpdatedItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeUpdatedItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec, a0 ERABToBeUpdatedItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec, a0 ERABToBeUpdatedItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERBudget(v *ERABToBeUpdatedItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERBudgetValue(v *ERABToBeUpdatedItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERChanged(v *ERABToBeUpdatedItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERChangedValue(v *ERABToBeUpdatedItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERLegacy(v *ERABToBeUpdatedItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERNewValue(v *ERABToBeUpdatedItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERPlanned(v *ERABToBeUpdatedItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemMethodMarshalAPERTo(v *ERABToBeUpdatedItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeUpdatedItemMethodUnmarshalAPERFrom(v *ERABToBeUpdatedItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeUpdatedItemMethodUnmarshalAPERLegacy(v *ERABToBeUpdatedItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeUpdatedItemMethodUnmarshalAPERWithOptions(v *ERABToBeUpdatedItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeUpdatedItemValueCodecFieldCapture(v *ERABToBeUpdatedItemValueCodec) *func(ERABToBeUpdatedItem, aper.DecodeState) (ERABToBeUpdatedItem, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemValueCodecFieldCompare(v *ERABToBeUpdatedItemValueCodec) *func(ERABToBeUpdatedItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemValueCodecFieldContext(v *ERABToBeUpdatedItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemValueCodecFieldDecode(v *ERABToBeUpdatedItemValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItem, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemValueCodecFieldEncode(v *ERABToBeUpdatedItemValueCodec) *func(ERABToBeUpdatedItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemValueCodecFieldPath(v *ERABToBeUpdatedItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemValueCodecMethodEncodeBudgetValue(v ERABToBeUpdatedItemValueCodec, a0 ERABToBeUpdatedItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedItemValueCodecMethodEncodeChanged(v ERABToBeUpdatedItemValueCodec, a0 ERABToBeUpdatedItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeUpdatedListAPERValueFieldContext(v *ERABToBeUpdatedListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedListAPERValueFieldReceived(v *ERABToBeUpdatedListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeUpdatedListAPERValueFieldReplay(v *ERABToBeUpdatedListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedListAPERValueFieldWithoutReplay(v *ERABToBeUpdatedListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedListValueCodecFieldCapture(v *ERABToBeUpdatedListValueCodec) *func(ERABToBeUpdatedList, aper.DecodeState) (ERABToBeUpdatedList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedListValueCodecFieldCompare(v *ERABToBeUpdatedListValueCodec) *func(ERABToBeUpdatedList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedListValueCodecFieldContext(v *ERABToBeUpdatedListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedListValueCodecFieldDecode(v *ERABToBeUpdatedListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedList, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedListValueCodecFieldEncode(v *ERABToBeUpdatedListValueCodec) *func(ERABToBeUpdatedList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedListValueCodecFieldPath(v *ERABToBeUpdatedListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedListValueCodecMethodEncodeBudgetValue(v ERABToBeUpdatedListValueCodec, a0 ERABToBeUpdatedList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedListValueCodecMethodEncodeChanged(v ERABToBeUpdatedListValueCodec, a0 ERABToBeUpdatedList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecurityIndicationAPERValueFieldContext(v *SecurityIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityIndicationAPERValueFieldReceived(v *SecurityIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecurityIndicationAPERValueFieldReplay(v *SecurityIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecurityIndicationAPERValueFieldWithoutReplay(v *SecurityIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecurityIndicationValueCodecFieldCapture(v *SecurityIndicationValueCodec) *func(s28.SecurityIndication, aper.DecodeState) (s28.SecurityIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityIndicationValueCodecFieldCompare(v *SecurityIndicationValueCodec) *func(s28.SecurityIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityIndicationValueCodecFieldContext(v *SecurityIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityIndicationValueCodecFieldDecode(v *SecurityIndicationValueCodec) *func([]byte, aper.DecodeState) (s28.SecurityIndication, error) {
	return &v.decode
}
func BridgeSecurityIndicationValueCodecFieldEncode(v *SecurityIndicationValueCodec) *func(s28.SecurityIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityIndicationValueCodecFieldPath(v *SecurityIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityIndicationValueCodecMethodEncodeBudgetValue(v SecurityIndicationValueCodec, a0 s28.SecurityIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecurityIndicationValueCodecMethodEncodeChanged(v SecurityIndicationValueCodec, a0 s28.SecurityIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
