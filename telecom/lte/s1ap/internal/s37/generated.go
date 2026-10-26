// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s37 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s37

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
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
func BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *ERABInformationListItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionContainer(v *ERABInformationListItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionContainer(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.SecurityIndicationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.SecurityIndicationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABInformationListIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABInformationListIEs}} of TS 36.413: a single information element field.
type ERABInformationListIEValueProtocolIESingleContainer = ERABInformationListIEField

// ERABInformationListItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABInformationListItem-ExtIEs}} of TS 36.413: a list of ERABInformationListItemExtIEsExtField values.
type ERABInformationListItemExtIEsExtContainer []ERABInformationListItemExtIEsExtField

// ERABInformationListItemExtIEsExtField is ProtocolExtensionField {{E-RABInformationListItem-ExtIEs}} of TS 36.413: an extension field.
type ERABInformationListItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABInformationListItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsExtField) WithoutReplay() ERABInformationListItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABInformationListItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABInformationListItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ERABInformationListItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABInformationListItemExtIEsExtField{}
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
	var zero ERABInformationListItemExtIEsValue

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

// ERABToBeSetupItemHOReqExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeSetupItemHOReq-ExtIEs}} of TS 36.413: a list of ERABToBeSetupItemHOReqExtIEsExtField values.
type ERABToBeSetupItemHOReqExtIEsExtContainer []ERABToBeSetupItemHOReqExtIEsExtField

// ERABToBeSwitchedDLItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeSwitchedDLItem-ExtIEs}} of TS 36.413: a list of ERABToBeSwitchedDLItemExtIEsExtField values.
type ERABToBeSwitchedDLItemExtIEsExtContainer []ERABToBeSwitchedDLItemExtIEsExtField

// ERABToBeUpdatedItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABToBeUpdatedItemIEs}} of TS 36.413: a single information element field.
type ERABToBeUpdatedItemIEValueProtocolIESingleContainer = ERABToBeUpdatedItemIEField

// ERABToBeSetupItemBearerSUReqExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeSetupItemBearerSUReqExtIEs}} of TS 36.413: a list of ERABToBeSetupItemBearerSUReqExtIEsExtField values.
type ERABToBeSetupItemBearerSUReqExtIEsExtContainer []ERABToBeSetupItemBearerSUReqExtIEsExtField

// ERABToBeSetupItemCtxtSUReqExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeSetupItemCtxtSUReqExtIEs}} of TS 36.413: a list of ERABToBeSetupItemCtxtSUReqExtIEsExtField values.
type ERABToBeSetupItemCtxtSUReqExtIEsExtContainer []ERABToBeSetupItemCtxtSUReqExtIEsExtField

// ERABToBeSetupItemHOReqExtIEsExtField is ProtocolExtensionField {{E-RABToBeSetupItemHOReq-ExtIEs}} of TS 36.413: an extension field.
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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

// ERABToBeSwitchedDLItemExtIEsExtField is ProtocolExtensionField {{E-RABToBeSwitchedDLItem-ExtIEs}} of TS 36.413: an extension field.
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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

// ERABToBeSetupItemBearerSUReqExtIEsExtField is ProtocolExtensionField {{E-RABToBeSetupItemBearerSUReqExtIEs}} of TS 36.413: an extension field.
type ERABToBeSetupItemBearerSUReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeSetupItemBearerSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtField) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemBearerSUReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemBearerSUReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ERABToBeSetupItemBearerSUReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemBearerSUReqExtIEsExtField{}
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
	var zero ERABToBeSetupItemBearerSUReqExtIEsValue

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

// ERABToBeSetupItemCtxtSUReqExtIEsExtField is ProtocolExtensionField {{E-RABToBeSetupItemCtxtSUReqExtIEs}} of TS 36.413: an extension field.
type ERABToBeSetupItemCtxtSUReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeSetupItemCtxtSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtField) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemCtxtSUReqExtIEsExtField{}
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
	var zero ERABToBeSetupItemCtxtSUReqExtIEsValue

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

// ERABInformationListERABInformationListItemIEBinding binds ERABInformationListItem to the E-RABInformationListIEs object set of TS 36.413.
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

// ERABInformationListIEField is ProtocolIE-Field {{E-RABInformationListIEs}} of TS 36.413: an information element field.
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

// ERABInformationListItemExtIEsDAPSRequestInfoExtBinding binds DAPSRequestInfo to the E-RABInformationListItem-ExtIEs object set of TS 36.413.
type ERABInformationListItemExtIEsDAPSRequestInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  s17.DAPSRequestInfoValueCodec
	inject func(s17.DAPSRequestInfo,

	) ERABInformationListItemExtIEsValue

	get func(*ERABInformationListItemExtIEsValue,

	) (*s17.DAPSRequestInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) Codec() s17.DAPSRequestInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) New(value s17.DAPSRequestInfo,

) (ERABInformationListItemExtIEsExtField, error) {
	if b.inject == nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeDAPSRequestInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABInformationListItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) Get(field *ERABInformationListItemExtIEsExtField) (*s17.DAPSRequestInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABInformationListItemExtIEsTransportLayerAddressExtBinding binds TransportLayerAddress to the E-RABInformationListItem-ExtIEs object set of TS 36.413.
type ERABInformationListItemExtIEsTransportLayerAddressExtBinding struct {
	info   s00.ExtensionInfo
	codec  s02.TransportLayerAddressValueCodec
	inject func(s00.TransportLayerAddress,

	) ERABInformationListItemExtIEsValue

	get func(*ERABInformationListItemExtIEsValue,

	) (*s00.TransportLayerAddress,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) Codec() s02.TransportLayerAddressValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) New(value s00.TransportLayerAddress,

) (ERABInformationListItemExtIEsExtField, error) {
	if b.inject == nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABInformationListItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) Get(field *ERABInformationListItemExtIEsExtField) (*s00.TransportLayerAddress,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABInformationListItemExtIEsSecurityIndicationExtBinding binds SecurityIndication to the E-RABInformationListItem-ExtIEs object set of TS 36.413.
type ERABInformationListItemExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(SecurityIndication,

	) ERABInformationListItemExtIEsValue

	get func(*ERABInformationListItemExtIEsValue,

	) (*SecurityIndication,

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
func (b ERABInformationListItemExtIEsSecurityIndicationExtBinding) New(value SecurityIndication,

) (ERABInformationListItemExtIEsExtField, error) {
	if b.inject == nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABInformationListItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABInformationListItemExtIEsSecurityIndicationExtBinding) Get(field *ERABInformationListItemExtIEsExtField) (*SecurityIndication,

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
	decode  func([]byte, aper.DecodeState) (SecurityIndication,

		error)
	encode func(SecurityIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityIndication, aper.DecodeState,

	) (SecurityIndication, aper.Snapshot,

	)
	compare func(SecurityIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityIndicationValueCodec) New(value SecurityIndication,

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
func (c SecurityIndicationValueCodec) encodeBudgetValue(value SecurityIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityIndicationValueCodec) encodeChanged(value SecurityIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding binds CorrelationID to the E-RABToBeSetupItemBearerSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.CorrelationIDValueCodec
	inject func(s00.CorrelationID,

	) ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*s00.CorrelationID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) Codec() s00.CorrelationIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) New(value s00.CorrelationID,

) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCorrelationIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) Get(field *ERABToBeSetupItemBearerSUReqExtIEsExtField) (*s00.CorrelationID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding binds BearerType to the E-RABToBeSetupItemBearerSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.BearerTypeValueCodec
	inject func(s00.BearerType,

	) ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*s00.BearerType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) Codec() s00.BearerTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) New(value s00.BearerType,

) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeBearerTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) Get(field *ERABToBeSetupItemBearerSUReqExtIEsExtField) (*s00.BearerType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding binds EthernetType to the E-RABToBeSetupItemBearerSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.EthernetTypeValueCodec
	inject func(s00.EthernetType,

	) ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*s00.EthernetType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) Codec() s00.EthernetTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) New(value s00.EthernetType,

) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEthernetTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) Get(field *ERABToBeSetupItemBearerSUReqExtIEsExtField) (*s00.EthernetType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding binds SecurityIndication to the E-RABToBeSetupItemBearerSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(SecurityIndication,

	) ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*SecurityIndication,

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
func (b ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) New(value SecurityIndication,

) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsSecurityIndicationExtBinding) Get(field *ERABToBeSetupItemBearerSUReqExtIEsExtField) (*SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding binds CorrelationID to the E-RABToBeSetupItemCtxtSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.CorrelationIDValueCodec
	inject func(s00.CorrelationID,

	) ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*s00.CorrelationID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) Codec() s00.CorrelationIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) New(value s00.CorrelationID,

) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCorrelationIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) Get(field *ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*s00.CorrelationID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding binds BearerType to the E-RABToBeSetupItemCtxtSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.BearerTypeValueCodec
	inject func(s00.BearerType,

	) ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*s00.BearerType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) Codec() s00.BearerTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) New(value s00.BearerType,

) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeBearerTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) Get(field *ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*s00.BearerType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding binds EthernetType to the E-RABToBeSetupItemCtxtSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.EthernetTypeValueCodec
	inject func(s00.EthernetType,

	) ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*s00.EthernetType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) Codec() s00.EthernetTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) New(value s00.EthernetType,

) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEthernetTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) Get(field *ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*s00.EthernetType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding binds SecurityIndication to the E-RABToBeSetupItemCtxtSUReqExtIEs object set of TS 36.413.
type ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(SecurityIndication,

	) ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*SecurityIndication,

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
func (b ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) New(value SecurityIndication,

) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsSecurityIndicationExtBinding) Get(field *ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemHOReqExtIEsDataForwardingNotPossibleExtBinding binds DataForwardingNotPossible to the E-RABToBeSetupItemHOReq-ExtIEs object set of TS 36.413.
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

// ERABToBeSetupItemHOReqExtIEsBearerTypeExtBinding binds BearerType to the E-RABToBeSetupItemHOReq-ExtIEs object set of TS 36.413.
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

// ERABToBeSetupItemHOReqExtIEsEthernetTypeExtBinding binds EthernetType to the E-RABToBeSetupItemHOReq-ExtIEs object set of TS 36.413.
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

// ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding binds SecurityIndication to the E-RABToBeSetupItemHOReq-ExtIEs object set of TS 36.413.
type ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(SecurityIndication,

	) ERABToBeSetupItemHOReqExtIEsValue

	get func(*ERABToBeSetupItemHOReqExtIEsValue,

	) (*SecurityIndication,

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
func (b ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) New(value SecurityIndication,

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
func (b ERABToBeSetupItemHOReqExtIEsSecurityIndicationExtBinding) Get(field *ERABToBeSetupItemHOReqExtIEsExtField) (*SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding binds SecurityIndication to the E-RABToBeSwitchedDLItem-ExtIEs object set of TS 36.413.
type ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  SecurityIndicationValueCodec
	inject func(SecurityIndication,

	) ERABToBeSwitchedDLItemExtIEsValue

	get func(*ERABToBeSwitchedDLItemExtIEsValue,

	) (*SecurityIndication,

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
func (b ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) New(value SecurityIndication,

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
func (b ERABToBeSwitchedDLItemExtIEsSecurityIndicationExtBinding) Get(field *ERABToBeSwitchedDLItemExtIEsExtField) (*SecurityIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeUpdatedItemERABToBeUpdatedItemIEBinding binds ERABToBeUpdatedItem to the E-RABToBeUpdatedItemIEs object set of TS 36.413.
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

// ERABToBeUpdatedItemIEField is ProtocolIE-Field {{E-RABToBeUpdatedItemIEs}} of TS 36.413: an information element field.
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
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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

// ERABInformationListIEContainer is ProtocolIE-Container {{E-RABInformationListIEs}} of TS 36.413: a list of ERABInformationListIEField values.
type ERABInformationListIEContainer []ERABInformationListIEField

func BridgeERABInformationListItemExtIEsValueValidateS1APExtensionContainer(fields ERABInformationListItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[ERABInformationListItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(ERABInformationListItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeERABInformationListItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ERABToBeUpdatedItemIEContainer is ProtocolIE-Container {{E-RABToBeUpdatedItemIEs}} of TS 36.413: a list of ERABToBeUpdatedItemIEField values.
type ERABToBeUpdatedItemIEContainer []ERABToBeUpdatedItemIEField

func BridgeSecurityContextExtIEsValueValidateS1APExtensionContainer(fields s13.SecurityContextExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.SecurityContextExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.SecurityContextExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSecurityContextExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ERABInformationListIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABInformationListIEs}} codec of TS 36.413.
func ERABInformationListIEValueERABIEContainerListCodec(table s00.ERABInformationListIEValueIETable) ERABInformationListIEValueERABIEContainerListValueCodec {
	codec := ERABInformationListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABInformationListIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ERABInformationListIEValueERABIEContainerListValueCodec{path: "ERABInformationListIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABInformationListIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABInformationListIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABInformationListIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ERABInformationListIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABInformationListIEContainer(value), fresh, budget)
	}, capture: func(v ERABInformationListIEValueERABIEContainerList, options aper.DecodeState) (ERABInformationListIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABInformationListIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ERABInformationListIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABInformationListIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ERABInformationListItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABInformationListItem-ExtIEs}} codec of TS 36.413.
func ERABInformationListItemExtIEsValueExtensionFieldTableCodec(table s00.ERABInformationListItemExtIEsValueExtensionTable) ERABInformationListItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABInformationListItemExtIEsValueExtensionTableFieldBound(&table) {
		return ERABInformationListItemExtIEsExtFieldValueCodec{}
	}
	return ERABInformationListItemExtIEsExtFieldValueCodec{path: "ERABInformationListItemExtIEsExtField", decode: func(data []byte, options aper.DecodeState) (ERABInformationListItemExtIEsExtField, error) {
		var field ERABInformationListItemExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABInformationListItemExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABInformationListItemExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABInformationListItemExtIEsExtField")
		}
		return field, nil
	}, encode: func(field ERABInformationListItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABInformationListItemExtIEsExtField, options aper.DecodeState) (ERABInformationListItemExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ERABInformationListItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ERABToBeSetupItemBearerSUReqExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABToBeSetupItemBearerSUReqExtIEs}} codec of TS 36.413.
func ERABToBeSetupItemBearerSUReqExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTable) ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableFieldBound(&table) {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec{}
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec{path: "ERABToBeSetupItemBearerSUReqExtIEsExtField", decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
		var field ERABToBeSetupItemBearerSUReqExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReqExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABToBeSetupItemBearerSUReqExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReqExtIEsExtField")
		}
		return field, nil
	}, encode: func(field ERABToBeSetupItemBearerSUReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABToBeSetupItemBearerSUReqExtIEsExtField, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ERABToBeSetupItemBearerSUReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SecurityIndicationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SecurityIndication-ExtIEs}} codec of TS 36.413.
func SecurityIndicationExtIEsValueExtensionFieldTableCodec(table s00.SecurityIndicationExtIEsValueExtensionTable) s13.SecurityIndicationExtIEsExtFieldValueCodec {
	if !*s00.BridgeSecurityIndicationExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SecurityIndicationExtIEsExtFieldValueCodec{}
	}
	return func() s13.SecurityIndicationExtIEsExtFieldValueCodec {
		sealed := s13.SecurityIndicationExtIEsExtFieldValueCodec{}
		*s13.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldPath(&sealed) = "SecurityIndicationExtIEsExtField"
		*s13.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SecurityIndicationExtIEsExtField, error) {
			var field s13.SecurityIndicationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeSecurityIndicationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SecurityIndicationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecurityIndicationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SecurityIndicationExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.SecurityIndicationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeSecurityIndicationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.SecurityIndicationExtIEsExtField, options aper.DecodeState) (s13.SecurityIndicationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.SecurityIndicationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABInformationListItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABInformationListItem-ExtIEs}} codec of TS 36.413.
func ERABInformationListItemExtIEsValueExtensionTableCodec(table s00.ERABInformationListItemExtIEsValueExtensionTable, bounds aper.ListBounds) ERABInformationListItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABInformationListItemExtIEsValueExtensionTableFieldBound(&table) {
		return ERABInformationListItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABInformationListItemExtIEsExtContainerValueCodec{path: "ERABInformationListItemExtIEsExtContainer", decode: func(data []byte, options aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABInformationListItemExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABInformationListItemExtIEsExtField
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
			return nil, runtime.WrapDecodePath(err, "ERABInformationListItemExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABInformationListItemExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABInformationListItemExtIEsExtContainer")
		}
		return fields, nil
	},
		encode: func(fields ERABInformationListItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABInformationListItemExtIEsExtContainer, options aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABInformationListItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

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

// ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABToBeSetupItemBearerSUReqExtIEs}} codec of TS 36.413.
func ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableCodec(table s00.ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTable, bounds aper.ListBounds) ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableFieldBound(&table) {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec{path: "ERABToBeSetupItemBearerSUReqExtIEsExtContainer", decode: func(data []byte, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABToBeSetupItemBearerSUReqExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABToBeSetupItemBearerSUReqExtIEsExtField
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
			return nil, runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReqExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABToBeSetupItemBearerSUReqExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReqExtIEsExtContainer")
		}
		return fields, nil
	},
		encode: func(fields ERABToBeSetupItemBearerSUReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABToBeSetupItemBearerSUReqExtIEsExtContainer, options aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSetupItemBearerSUReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

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

// SecurityIndicationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SecurityIndication-ExtIEs}} codec of TS 36.413.
func SecurityIndicationExtIEsValueExtensionTableCodec(table s00.SecurityIndicationExtIEsValueExtensionTable, bounds aper.ListBounds) s13.SecurityIndicationExtIEsExtContainerValueCodec {
	if !*s00.BridgeSecurityIndicationExtIEsValueExtensionTableFieldBound(&table) {
		return s13.SecurityIndicationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.SecurityIndicationExtIEsExtContainerValueCodec {
		sealed := s13.SecurityIndicationExtIEsExtContainerValueCodec{}
		*s13.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldPath(&sealed) = "SecurityIndicationExtIEsExtContainer"
		*s13.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.SecurityIndicationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.SecurityIndicationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.SecurityIndicationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeSecurityIndicationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "SecurityIndicationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecurityIndicationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SecurityIndicationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s13.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.SecurityIndicationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeSecurityIndicationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.SecurityIndicationExtIEsExtContainer, options aper.DecodeState) (s13.SecurityIndicationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.SecurityIndicationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABInformationListIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABInformationListIEs}} codec of TS 36.413.
func ERABInformationListIEValueIEFieldTableCodec(table s00.ERABInformationListIEValueIETable) ERABInformationListIEFieldValueCodec {
	if !*s00.BridgeERABInformationListIEValueIETableFieldBound(&table) {
		return ERABInformationListIEFieldValueCodec{}
	}
	return ERABInformationListIEFieldValueCodec{path: "ERABInformationListIEField", decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEField, error) {
		var field ERABInformationListIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABInformationListIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABInformationListIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ERABInformationListIEField")
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
		BridgeERABInformationListIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
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

// ERABInformationListIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABInformationListIEs}} codec of TS 36.413.
func ERABInformationListIEValueIETableCodec(table s00.ERABInformationListIEValueIETable, bounds aper.ListBounds) ERABInformationListIEContainerValueCodec {
	if !*s00.BridgeERABInformationListIEValueIETableFieldBound(&table) {
		return ERABInformationListIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABInformationListIEContainerValueCodec{path: "ERABInformationListIEContainer", decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABInformationListIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABInformationListIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABInformationListIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ERABInformationListIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABInformationListIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ERABInformationListIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABInformationListIEs}} codec of TS 36.413.
func ERABInformationListIEValueProtocolErrorIEContainerListCodec(table s00.ERABInformationListIEValueIETable) ERABInformationListIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABInformationListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABInformationListIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ERABInformationListIEValueProtocolErrorIEContainerListValueCodec{path: "ERABInformationListIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABInformationListIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABInformationListIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABInformationListIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
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
		f := s.Begin()
		BridgeERABInformationListIEValueCompareS1APProtocolErrorIEContainerList(
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

// ERABInformationListIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABInformationListIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABInformationListIEValueProtocolIEContainerListCodec(table s00.ERABInformationListIEValueIETable, bounds aper.ListBounds) ERABInformationListIEValueProtocolIEContainerListValueCodec {
	codec := ERABInformationListIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABInformationListIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ERABInformationListIEValueProtocolIEContainerListValueCodec{path: "ERABInformationListIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABInformationListIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABInformationListIEField
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
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABInformationListIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABInformationListIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ERABInformationListIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABInformationListIEContainer(value), fresh, budget)
	}, capture: func(v ERABInformationListIEValueProtocolIEContainerList, options aper.DecodeState) (ERABInformationListIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABInformationListIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ERABInformationListIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeERABInformationListIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABInformationListItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABInformationListItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABInformationListItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABInformationListItemExtIEsValueCaptureS1APProtocolExtensionField(v *ERABInformationListItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABInformationListItemExtIEsValueCompareS1APProtocolExtensionField(v *ERABInformationListItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCaptureS1APProtocolExtensionField(v *ERABToBeSetupItemBearerSUReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionField(v *ERABToBeSetupItemBearerSUReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// securityContextExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SecurityContextExtIEsValue].
type SecurityContextExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SecurityContextExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SecurityContextExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionField(v *s13.SecurityIndicationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSecurityIndicationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeSecurityIndicationExtIEsExtFieldFieldReplay(v), *s13.BridgeSecurityIndicationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionField(v *s13.SecurityIndicationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSecurityIndicationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeSecurityIndicationExtIEsExtFieldFieldReplay(v), *s13.BridgeSecurityIndicationExtIEsExtFieldFieldWithoutReplay(v))
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
	Value   SecurityIndication

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

// ERABInformationListItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABInformationListItem-ExtIEs of TS 36.413.
type ERABInformationListItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABInformationListItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsIEField) WithoutReplay() ERABInformationListItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABInformationListItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABInformationListItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABInformationListItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABInformationListItemExtIEsIEField{}
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
	var zero ERABInformationListItemExtIEsValue

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

// ERABInformationListItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABInformationListItem-ExtIEs of TS 36.413: a list of ERABInformationListItemExtIEsIEField values.
type ERABInformationListItemExtIEsIEContainer []ERABInformationListItemExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABInformationListItemExtIEsValueValidateS1APIEContainer(fields ERABInformationListItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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

// ERABToBeSetupItemBearerSUReqExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeSetupItemBearerSUReqExtIEs of TS 36.413.
type ERABToBeSetupItemBearerSUReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemBearerSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsIEField) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemBearerSUReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemBearerSUReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemBearerSUReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemBearerSUReqExtIEsIEField{}
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
	var zero ERABToBeSetupItemBearerSUReqExtIEsValue

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

// ERABToBeSetupItemBearerSUReqExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeSetupItemBearerSUReqExtIEs of TS 36.413: a list of ERABToBeSetupItemBearerSUReqExtIEsIEField values.
type ERABToBeSetupItemBearerSUReqExtIEsIEContainer []ERABToBeSetupItemBearerSUReqExtIEsIEField

// ERABToBeSetupItemCtxtSUReqExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeSetupItemCtxtSUReqExtIEs of TS 36.413.
type ERABToBeSetupItemCtxtSUReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemCtxtSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsIEField) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemCtxtSUReqExtIEsIEField{}
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
	var zero ERABToBeSetupItemCtxtSUReqExtIEsValue

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

// ERABToBeSetupItemCtxtSUReqExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeSetupItemCtxtSUReqExtIEs of TS 36.413: a list of ERABToBeSetupItemCtxtSUReqExtIEsIEField values.
type ERABToBeSetupItemCtxtSUReqExtIEsIEContainer []ERABToBeSetupItemCtxtSUReqExtIEsIEField

// ERABToBeSetupItemHOReqExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeSetupItemHOReq-ExtIEs of TS 36.413.
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

// ERABToBeSetupItemHOReqExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeSetupItemHOReq-ExtIEs of TS 36.413: a list of ERABToBeSetupItemHOReqExtIEsIEField values.
type ERABToBeSetupItemHOReqExtIEsIEContainer []ERABToBeSetupItemHOReqExtIEsIEField

// ERABToBeSwitchedDLItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeSwitchedDLItem-ExtIEs of TS 36.413.
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

// ERABToBeSwitchedDLItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeSwitchedDLItem-ExtIEs of TS 36.413: a list of ERABToBeSwitchedDLItemExtIEsIEField values.
type ERABToBeSwitchedDLItemExtIEsIEContainer []ERABToBeSwitchedDLItemExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSecurityContextExtIEsValueValidateS1APIEContainer(fields s13.SecurityContextExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSecurityContextExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSecurityContextExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSecurityContextExtIEsValueMethodRule(field.Value).Assignment
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

// ERABInformationListIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABInformationListIEValueERABIEContainerList].
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

// ERABInformationListIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABInformationListIEs}} of TS 36.413: a list of information element fields.
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

// ERABToBeUpdatedItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABToBeUpdatedItemIEValueERABIEContainerList].
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

// ERABToBeUpdatedItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABToBeUpdatedItemIEs}} of TS 36.413: a list of information element fields.
type ERABToBeUpdatedItemIEValueERABIEContainerList []ERABToBeUpdatedItemIEValueProtocolIESingleContainer

// ERABInformationListItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABInformationListItemExtIEsExtField].
type ERABInformationListItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListItemExtIEsExtField, error)
	encode  func(ERABInformationListItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListItemExtIEsExtField, aper.DecodeState) (ERABInformationListItemExtIEsExtField, aper.Snapshot)
	compare func(ERABInformationListItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListItemExtIEsExtFieldValueCodec) New(value ERABInformationListItemExtIEsExtField) (ERABInformationListItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABInformationListItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABInformationListItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListItemExtIEsExtFieldValueCodec) encodeChanged(value ERABInformationListItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeSetupItemBearerSUReqExtIEsExtField].
type ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error)
	encode  func(ERABToBeSetupItemBearerSUReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) New(value ERABToBeSetupItemBearerSUReqExtIEsExtField) (ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeSetupItemCtxtSUReqExtIEsExtField].
type ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error)
	encode  func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) New(value ERABToBeSetupItemCtxtSUReqExtIEsExtField) (ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeSetupItemHOReqExtIEsExtField].
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

// ERABToBeSwitchedDLItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeSwitchedDLItemExtIEsExtField].
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

// ERABInformationListItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABInformationListItemExtIEsExtContainer].
type ERABInformationListItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, error)
	encode  func(ERABInformationListItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListItemExtIEsExtContainer, aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABInformationListItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListItemExtIEsExtContainerValueCodec) New(value ERABInformationListItemExtIEsExtContainer) (ERABInformationListItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABInformationListItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABInformationListItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListItemExtIEsExtContainerValueCodec) encodeChanged(value ERABInformationListItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeSetupItemBearerSUReqExtIEsExtContainer].
type ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, error)
	encode  func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) New(value ERABToBeSetupItemBearerSUReqExtIEsExtContainer) (ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeSetupItemCtxtSUReqExtIEsExtContainer].
type ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, error)
	encode  func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) New(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainer) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemHOReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeSetupItemHOReqExtIEsExtContainer].
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

// ERABToBeSwitchedDLItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeSwitchedDLItemExtIEsExtContainer].
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

// ERABInformationListIEFieldValueCodec is the concrete ValueCodec[ERABInformationListIEField].
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

// ERABToBeUpdatedItemIEFieldValueCodec is the concrete ValueCodec[ERABToBeUpdatedItemIEField].
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

// ERABInformationListIEContainerValueCodec is the concrete ValueCodec[ERABInformationListIEContainer].
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

// ERABToBeUpdatedItemIEContainerValueCodec is the concrete ValueCodec[ERABToBeUpdatedItemIEContainer].
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

// ERABInformationListIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABInformationListIEValueProtocolErrorIEContainerList].
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

// ERABInformationListIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABInformationListIEs}} of TS 36.413: a list of information element fields.
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

// ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList].
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

// ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABToBeUpdatedItemIEs}} of TS 36.413: a list of information element fields.
type ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList []ERABToBeUpdatedItemIEValueProtocolIESingleContainer

// ERABInformationListIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABInformationListIEValueProtocolIEContainerList].
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

// ERABInformationListIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABInformationListIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
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

// ERABToBeUpdatedItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABToBeUpdatedItemIEValueProtocolIEContainerList].
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

// ERABToBeUpdatedItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeUpdatedItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABToBeUpdatedItemIEValueProtocolIEContainerList []ERABToBeUpdatedItemIEValueProtocolIESingleContainer

// ERABInformationListIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABInformationListIEValueERABIEContainerList].
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

// ERABToBeUpdatedItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABToBeUpdatedItemIEValueERABIEContainerList].
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

// ERABInformationListItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABInformationListItemExtIEsExtField].
type ERABInformationListItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsExtFieldAPERValue) WithoutReplay() ERABInformationListItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeSetupItemBearerSUReqExtIEsExtField].
type ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeSetupItemCtxtSUReqExtIEsExtField].
type ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeSetupItemHOReqExtIEsExtField].
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

// ERABToBeSwitchedDLItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeSwitchedDLItemExtIEsExtField].
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

// ERABInformationListItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABInformationListItemExtIEsExtContainer].
type ERABInformationListItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsExtContainerAPERValue) WithoutReplay() ERABInformationListItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeSetupItemBearerSUReqExtIEsExtContainer].
type ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeSetupItemCtxtSUReqExtIEsExtContainer].
type ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemHOReqExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeSetupItemHOReqExtIEsExtContainer].
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

// ERABToBeSwitchedDLItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeSwitchedDLItemExtIEsExtContainer].
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

// ERABInformationListIEFieldAPERValue is the concrete APERValue[ERABInformationListIEField].
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

// ERABToBeUpdatedItemIEFieldAPERValue is the concrete APERValue[ERABToBeUpdatedItemIEField].
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

// ERABInformationListIEContainerAPERValue is the concrete APERValue[ERABInformationListIEContainer].
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

// ERABToBeUpdatedItemIEContainerAPERValue is the concrete APERValue[ERABToBeUpdatedItemIEContainer].
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

// ERABInformationListIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABInformationListIEValueProtocolErrorIEContainerList].
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

// ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABToBeUpdatedItemIEValueProtocolErrorIEContainerList].
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

// ERABInformationListIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABInformationListIEValueProtocolIEContainerList].
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

// ERABToBeUpdatedItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABToBeUpdatedItemIEValueProtocolIEContainerList].
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
func BridgeCaptureS1APERABInformationListItemExtIEsValue(v *ERABInformationListItemExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(317):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSRequestInfo == nil)
				if v.rowDAPSRequestInfo != nil {
					s17.BridgeCaptureS1APDAPSRequestInfo(v.rowDAPSRequestInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(328):
			{
				f := s.Begin()
				s.Bool(v.rowSourceTransportLayerAddress == nil)
				if v.rowSourceTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowSourceTransportLayerAddress, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(340):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeTransportLayerAddress == nil)
				if v.rowSourceNodeTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowSourceNodeTransportLayerAddress, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABInformationListItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABInformationListItemExtIEsValue {
	BridgeCaptureS1APERABInformationListItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABInformationListItemExtIEsValue(v *ERABInformationListItemExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(317):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSRequestInfo == nil)
				if v.rowDAPSRequestInfo != nil {
					s17.BridgeCompareS1APDAPSRequestInfo(v.rowDAPSRequestInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(328):
			{
				f := s.Begin()
				s.Bool(v.rowSourceTransportLayerAddress == nil)
				if v.rowSourceTransportLayerAddress != nil {
					s08.BridgeCompareS1APTransportLayerAddress(v.rowSourceTransportLayerAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(340):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeTransportLayerAddress == nil)
				if v.rowSourceNodeTransportLayerAddress != nil {
					s08.BridgeCompareS1APTransportLayerAddress(v.rowSourceNodeTransportLayerAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABInformationListItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABInformationListItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupItemBearerSUReq(v *ERABToBeSetupItemBearerSUReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s21.BridgeCaptureS1APERABLevelQoSParameters(&v.ERABlevelQoSParameters, s)
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
	s21.BridgeCompareS1APERABLevelQoSParameters(&v.ERABlevelQoSParameters, s)
	s08.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	s02.BridgeCompareS1APNASPDU(&v.NASPDU, s)
	s.Bool(v.IEExtensions == nil)
	BridgeERABToBeSetupItemBearerSUReqExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupItemBearerSUReqExtIEsValue(v *ERABToBeSetupItemBearerSUReqExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowSIPTOCorrelationID, s)
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
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemBearerSUReqExtIEsValue {
	BridgeCaptureS1APERABToBeSetupItemBearerSUReqExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemBearerSUReqExtIEsValue(v *ERABToBeSetupItemBearerSUReqExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowSIPTOCorrelationID, s)
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
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemBearerSUReqExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupItemCtxtSUReqExtIEsValue(v *ERABToBeSetupItemCtxtSUReqExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowSIPTOCorrelationID, s)
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
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemCtxtSUReqExtIEsValue {
	BridgeCaptureS1APERABToBeSetupItemCtxtSUReqExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemCtxtSUReqExtIEsValue(v *ERABToBeSetupItemCtxtSUReqExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowSIPTOCorrelationID, s)
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
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemCtxtSUReqExtIEsValue(&v, &s)
	return s
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
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
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
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
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
			BridgeCaptureS1APSecurityIndication(v.SecurityIndication, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
			BridgeCompareS1APSecurityIndication(v.SecurityIndication, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
func BridgeCaptureS1APSecurityIndication(v *SecurityIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APIntegrityProtectionIndication(&v.IntegrityProtectionIndication, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecurityIndication(v *SecurityIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APIntegrityProtectionIndication(&v.IntegrityProtectionIndication, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
	ERABID            s00.ERABID                                `asn1:"tag:0,context,implicit"`
	DLForwarding      *s00.DLForwarding                         `asn1:"tag:1,context,implicit,optional" json:"DLForwarding,omitempty"`
	IEExtensions      ERABInformationListItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                      `asn1:"-" json:"-"`
	extCount          int64                                     `asn1:"-" json:"-"`
	extPresent        []bool                                    `asn1:"-" json:"-"`
	extData           [][]byte                                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// SecurityIndication represents the ASN.1 type SecurityIndication (SEQUENCE).
type SecurityIndication struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	IntegrityProtectionIndication s00.IntegrityProtectionIndication        `asn1:"tag:0,context,implicit"`
	IEExtensions                  s13.SecurityIndicationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                                     `asn1:"-" json:"-"`
	extCount                      int64                                    `asn1:"-" json:"-"`
	extPresent                    []bool                                   `asn1:"-" json:"-"`
	extData                       [][]byte                                 `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
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

// UnmarshalAPER decodes ERABInformationListItem from APER format.
func (v *ERABInformationListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ERABInformationListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABInformationListItem{}
	var extAdditions aper.ExtensionAdditions
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
		tmp_ieextensions := make(ERABInformationListItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ERABInformationListItemExtIEsExtField
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

// MarshalAPER encodes SecurityIndication to APER format.
func (v *SecurityIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SecurityIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.IntegrityProtectionIndication), 3, true); err != nil {
		return fmt.Errorf("encoding integrityProtectionIndication: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeSecurityIndicationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SecurityIndication from APER format.
func (v *SecurityIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SecurityIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecurityIndication")
	}
	bb.EnterComponent("SecurityIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecurityIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecurityIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecurityIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *SecurityIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityIndication{}
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
	val_integrityprotectionindication, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IntegrityProtectionIndication"})
	if err != nil {
		return runtime.WrapDecodePath(err, "IntegrityProtectionIndication")
	}
	v.IntegrityProtectionIndication = s00.IntegrityProtectionIndication(val_integrityprotectionindication)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.SecurityIndicationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.SecurityIndicationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeSecurityIndicationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ERABInformationListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABInformationListItem", v.receivedLocation, v.perPadding)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecurityIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecurityIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecurityIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecurityIndication) WithoutReplay() SecurityIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecurityIndication
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

// Extensions returns owned unknown sequence additions.
func (v *SecurityIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SecurityIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SecurityIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SecurityIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecurityIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecurityIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecurityIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecurityIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecurityIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecurityIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecurityIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecurityIndication")
}
func (v *SecurityIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecurityIndication")
}
func (v *SecurityIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecurityIndication(v, &s)
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
func (v *SecurityIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecurityIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecurityIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecurityIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecurityIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecurityIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecurityIndication{}
		return report, aper.OperationError(err, "SecurityIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecurityIndication")
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
	SecurityIndication *SecurityIndication                       `asn1:"tag:1,context,implicit,optional" json:"SecurityIndication,omitempty"`
	IEExtensions       s10.ERABToBeUpdatedItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                      `asn1:"-" json:"-"`
	extCount           int64                                     `asn1:"-" json:"-"`
	extPresent         []bool                                    `asn1:"-" json:"-"`
	extData            [][]byte                                  `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// ERABToBeSetupItemBearerSUReq represents the ASN.1 type E-RABToBeSetupItemBearerSUReq (SEQUENCE).
type ERABToBeSetupItemBearerSUReq struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	ERABID                 s00.ERABID                                     `asn1:"tag:0,context,implicit"`
	ERABlevelQoSParameters s21.ERABLevelQoSParameters                     `asn1:"tag:1,context,implicit"`
	TransportLayerAddress  s00.TransportLayerAddress                      `asn1:"tag:2,context,implicit"`
	GTPTEID                s00.GTPTEID                                    `asn1:"tag:3,context,implicit"`
	NASPDU                 s00.NASPDU                                     `asn1:"tag:4,context,implicit"`
	IEExtensions           ERABToBeSetupItemBearerSUReqExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                           `asn1:"-" json:"-"`
	extCount               int64                                          `asn1:"-" json:"-"`
	extPresent             []bool                                         `asn1:"-" json:"-"`
	extData                [][]byte                                       `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
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
		if err := v.SecurityIndication.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s10.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeUpdatedItem from APER format.
func (v *ERABToBeUpdatedItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ERABToBeUpdatedItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeUpdatedItem{}
	var extAdditions aper.ExtensionAdditions
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
		var dec_securityindication SecurityIndication
		if err := dec_securityindication.unmarshalAPERFrom(bb); err != nil {
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
		tmp_ieextensions := make(s10.ERABToBeUpdatedItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.ERABToBeUpdatedItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := s21.BridgeERABLevelQoSParametersMethodMarshalAPERTo(&v.ERABlevelQoSParameters, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeSetupItemBearerSUReq from APER format.
func (v *ERABToBeSetupItemBearerSUReq) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ERABToBeSetupItemBearerSUReq) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemBearerSUReq{}
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
	toleranceMark_erablevelqosparameters := bb.EnterComponent("ERABlevelQoSParameters")
	if err := s21.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&v.ERABlevelQoSParameters, bb); err != nil {
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
		tmp_ieextensions := make(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ERABToBeSetupItemBearerSUReqExtIEsExtField
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
func (v *ERABToBeSetupItemBearerSUReq) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSetupItemBearerSUReq", v.receivedLocation, v.perPadding)
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
func (v *ERABToBeUpdatedItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeUpdatedItem", v.receivedLocation, v.perPadding)
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

type ERABInformationListItemExtIEsValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowDAPSRequestInfo                 *s17.DAPSRequestInfo
	rowSourceTransportLayerAddress     *s00.TransportLayerAddress
	rowSecurityIndication              *SecurityIndication
	rowSourceNodeTransportLayerAddress *s00.TransportLayerAddress
}

func (v ERABInformationListItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(317):
		return v.rowDAPSRequestInfo != nil
	case s00.ProtocolIEID(328):
		return v.rowSourceTransportLayerAddress != nil
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	case s00.ProtocolIEID(340):
		return v.rowSourceNodeTransportLayerAddress != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABInformationListItemExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABInformationListItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABInformationListItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs"}}
}
func (ERABInformationListItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(317):
		return aper.UnknownSelector
	case s00.ProtocolIEID(328):
		return aper.UnknownSelector
	case s00.ProtocolIEID(332):
		return aper.UnknownSelector
	case s00.ProtocolIEID(340):
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

// AsDAPSRequestInfo returns the selected DAPSRequestInfo value of ERABInformationListItemExtIEsValue and reports whether that alternative is active.
func (v *ERABInformationListItemExtIEsValue) AsDAPSRequestInfo() (*s17.DAPSRequestInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(317) || v.rowDAPSRequestInfo == nil {
		return nil, false
	}
	return v.rowDAPSRequestInfo, true
}

// AsSourceTransportLayerAddress returns the selected SourceTransportLayerAddress value of ERABInformationListItemExtIEsValue and reports whether that alternative is active.
func (v *ERABInformationListItemExtIEsValue) AsSourceTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(328) || v.rowSourceTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowSourceTransportLayerAddress, true
}

// AsSecurityIndication returns the selected SecurityIndication value of ERABInformationListItemExtIEsValue and reports whether that alternative is active.
func (v *ERABInformationListItemExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}

// AsSourceNodeTransportLayerAddress returns the selected SourceNodeTransportLayerAddress value of ERABInformationListItemExtIEsValue and reports whether that alternative is active.
func (v *ERABInformationListItemExtIEsValue) AsSourceNodeTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(340) || v.rowSourceNodeTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowSourceNodeTransportLayerAddress, true
}
func (v ERABInformationListItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABInformationListItemExtIEsValue, error) {
	out := ERABInformationListItemExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(317):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.DAPSRequestInfo
		child := scope
		if err := s17.BridgeDAPSRequestInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "DAPSRequestInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DAPSRequestInfo")
		if err != nil {
			return out, err
		}
		*s17.BridgeDAPSRequestInfoFieldPerPadding(&value) = padding
		*s17.BridgeDAPSRequestInfoFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeDAPSRequestInfoFieldReceivedBytes(&value))
		*s17.BridgeDAPSRequestInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowDAPSRequestInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(328):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TransportLayerAddress, error) {
			var v struct{ Value s00.TransportLayerAddress }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
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
		out.rowSourceTransportLayerAddress = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(332):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSecurityIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(340):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TransportLayerAddress, error) {
			var v struct{ Value s00.TransportLayerAddress }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
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
		out.rowSourceNodeTransportLayerAddress = &value
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
func (v ERABInformationListItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABInformationListItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(317):
		if v.rowDAPSRequestInfo == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-DAPSRequestInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeDAPSRequestInfoMethodMarshalAPERBudget(v.rowDAPSRequestInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(328):
		if v.rowSourceTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-SourceTransportLayerAddress:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TransportLayerAddress, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.TransportLayerAddress }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 1, 160, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSourceTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(332):
		if v.rowSecurityIndication == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(340):
		if v.rowSourceNodeTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-SourceNodeTransportLayerAddress:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TransportLayerAddress, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.TransportLayerAddress }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 1, 160, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSourceNodeTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABInformationListItemExtIEsValue:", v.id)
	}
}

type ERABToBeSetupItemBearerSUReqExtIEsValue struct {
	id                    s00.ProtocolIEID
	received              aper.WireSpan
	replay                aper.Snapshot
	opaque                aper.OpaqueOpenType
	isOpaque              bool
	rowCorrelationID      *s00.CorrelationID
	rowSIPTOCorrelationID *s00.CorrelationID
	rowBearerType         *s00.BearerType
	rowEthernetType       *s00.EthernetType
	rowSecurityIndication *SecurityIndication
}

func (v ERABToBeSetupItemBearerSUReqExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(156):
		return v.rowCorrelationID != nil
	case s00.ProtocolIEID(183):
		return v.rowSIPTOCorrelationID != nil
	case s00.ProtocolIEID(233):
		return v.rowBearerType != nil
	case s00.ProtocolIEID(305):
		return v.rowEthernetType != nil
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSetupItemBearerSUReqExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemBearerSUReqExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs"}}
}
func (ERABToBeSetupItemBearerSUReqExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(156):
		return aper.UnknownSelector
	case s00.ProtocolIEID(183):
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

// AsCorrelationID returns the selected CorrelationID value of ERABToBeSetupItemBearerSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(156) || v.rowCorrelationID == nil {
		return nil, false
	}
	return v.rowCorrelationID, true
}

// AsSIPTOCorrelationID returns the selected SIPTOCorrelationID value of ERABToBeSetupItemBearerSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsSIPTOCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(183) || v.rowSIPTOCorrelationID == nil {
		return nil, false
	}
	return v.rowSIPTOCorrelationID, true
}

// AsBearerType returns the selected BearerType value of ERABToBeSetupItemBearerSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsBearerType() (*s00.BearerType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(233) || v.rowBearerType == nil {
		return nil, false
	}
	return v.rowBearerType, true
}

// AsEthernetType returns the selected EthernetType value of ERABToBeSetupItemBearerSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsEthernetType() (*s00.EthernetType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(305) || v.rowEthernetType == nil {
		return nil, false
	}
	return v.rowEthernetType, true
}

// AsSecurityIndication returns the selected SecurityIndication value of ERABToBeSetupItemBearerSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemBearerSUReqExtIEsValue, error) {
	out := ERABToBeSetupItemBearerSUReqExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(156):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowCorrelationID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(183):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowSIPTOCorrelationID = &value
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
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(156):
		if v.rowCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(183):
		if v.rowSIPTOCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-SIPTO-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSIPTOCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(233):
		if v.rowBearerType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-BearerType:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-Ethernet-Type:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemBearerSUReqExtIEsValue:", v.id)
	}
}

type ERABToBeSetupItemCtxtSUReqExtIEsValue struct {
	id                    s00.ProtocolIEID
	received              aper.WireSpan
	replay                aper.Snapshot
	opaque                aper.OpaqueOpenType
	isOpaque              bool
	rowCorrelationID      *s00.CorrelationID
	rowSIPTOCorrelationID *s00.CorrelationID
	rowBearerType         *s00.BearerType
	rowEthernetType       *s00.EthernetType
	rowSecurityIndication *SecurityIndication
}

func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(156):
		return v.rowCorrelationID != nil
	case s00.ProtocolIEID(183):
		return v.rowSIPTOCorrelationID != nil
	case s00.ProtocolIEID(233):
		return v.rowBearerType != nil
	case s00.ProtocolIEID(305):
		return v.rowEthernetType != nil
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSetupItemCtxtSUReqExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemCtxtSUReqExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs"}}
}
func (ERABToBeSetupItemCtxtSUReqExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(156):
		return aper.UnknownSelector
	case s00.ProtocolIEID(183):
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

// AsCorrelationID returns the selected CorrelationID value of ERABToBeSetupItemCtxtSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(156) || v.rowCorrelationID == nil {
		return nil, false
	}
	return v.rowCorrelationID, true
}

// AsSIPTOCorrelationID returns the selected SIPTOCorrelationID value of ERABToBeSetupItemCtxtSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsSIPTOCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(183) || v.rowSIPTOCorrelationID == nil {
		return nil, false
	}
	return v.rowSIPTOCorrelationID, true
}

// AsBearerType returns the selected BearerType value of ERABToBeSetupItemCtxtSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsBearerType() (*s00.BearerType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(233) || v.rowBearerType == nil {
		return nil, false
	}
	return v.rowBearerType, true
}

// AsEthernetType returns the selected EthernetType value of ERABToBeSetupItemCtxtSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsEthernetType() (*s00.EthernetType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(305) || v.rowEthernetType == nil {
		return nil, false
	}
	return v.rowEthernetType, true
}

// AsSecurityIndication returns the selected SecurityIndication value of ERABToBeSetupItemCtxtSUReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemCtxtSUReqExtIEsValue, error) {
	out := ERABToBeSetupItemCtxtSUReqExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(156):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowCorrelationID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(183):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowSIPTOCorrelationID = &value
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
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(156):
		if v.rowCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(183):
		if v.rowSIPTOCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-SIPTO-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSIPTOCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(233):
		if v.rowBearerType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-BearerType:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-Ethernet-Type:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemCtxtSUReqExtIEsValue:", v.id)
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
	rowSecurityIndication        *SecurityIndication
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
func (v *ERABToBeSetupItemHOReqExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
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
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemHOReqExtIEsValue:", v.id)
	}
}

type ERABToBeSwitchedDLItemExtIEsValue struct {
	id                    s00.ProtocolIEID
	received              aper.WireSpan
	replay                aper.Snapshot
	opaque                aper.OpaqueOpenType
	isOpaque              bool
	rowSecurityIndication *SecurityIndication
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
func (v *ERABToBeSwitchedDLItemExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
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
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
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
				return empty, runtime.WrapDecodePath(err, "ERABInformationListItem")
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
func (t ERABInformationListItemExtIETable) DAPSRequestInfo() ERABInformationListItemExtIEsDAPSRequestInfoExtBinding {
	return ERABInformationListItemExtIEsDAPSRequestInfoExtBinding{info: t.infoDAPSRequestInfo(), codec: func() s17.DAPSRequestInfoValueCodec {
		sealed := s17.DAPSRequestInfoValueCodec{}
		*s17.BridgeDAPSRequestInfoValueCodecFieldPath(&sealed) = "DAPSRequestInfo"
		*s17.BridgeDAPSRequestInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.DAPSRequestInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.DAPSRequestInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DAPSRequestInfo")
			var zero ERABInformationListItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(317), raw)
			if err != nil {
				var empty s17.DAPSRequestInfo
				return empty, runtime.WrapDecodePath(err, "DAPSRequestInfo")
			}
			value, ok := decoded.AsDAPSRequestInfo()
			if !ok {
				var empty s17.DAPSRequestInfo
				return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-DAPSRequestInfo: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeDAPSRequestInfoValueCodecFieldEncode(&sealed) = func(value s17.DAPSRequestInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(317), rowDAPSRequestInfo: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeDAPSRequestInfoValueCodecFieldCapture(&sealed) = func(v s17.DAPSRequestInfo, options aper.DecodeState) (s17.DAPSRequestInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APDAPSRequestInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeDAPSRequestInfoValueCodecFieldCompare(&sealed) = func(v s17.DAPSRequestInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APDAPSRequestInfo(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s17.BridgeDAPSRequestInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DAPSRequestInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.DAPSRequestInfo) ERABInformationListItemExtIEsValue {
			return ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(317), rowDAPSRequestInfo: &value}
		}, get: func(value *ERABInformationListItemExtIEsValue) (*s17.DAPSRequestInfo, bool) {
			return value.AsDAPSRequestInfo()
		}}
}
func (ERABInformationListItemExtIETable) infoSourceTransportLayerAddress() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABInformationListItemExtIEs().ID(), ID: s00.ProtocolExtensionID(328), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs", Row: "id-SourceTransportLayerAddress"}}}
}

// SourceTransportLayerAddress returns the typed binding for the SourceTransportLayerAddress row of ERABInformationListItemExtIETable.
func (t ERABInformationListItemExtIETable) SourceTransportLayerAddress() ERABInformationListItemExtIEsTransportLayerAddressExtBinding {
	return ERABInformationListItemExtIEsTransportLayerAddressExtBinding{info: t.infoSourceTransportLayerAddress(), codec: func() s02.TransportLayerAddressValueCodec {
		sealed := s02.TransportLayerAddressValueCodec{}
		*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
		*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
			var zero ERABInformationListItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(328), raw)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, runtime.WrapDecodePath(err, "TransportLayerAddress")
			}
			value, ok := decoded.AsSourceTransportLayerAddress()
			if !ok {
				var empty s00.TransportLayerAddress
				return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-SourceTransportLayerAddress: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(328), rowSourceTransportLayerAddress: &value}).encodeFresh(fresh, budget)
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
			s08.BridgeCompareS1APTransportLayerAddress(&v, &s)
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
	}(),
		inject: func(value s00.TransportLayerAddress) ERABInformationListItemExtIEsValue {
			return ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(328), rowSourceTransportLayerAddress: &value}
		}, get: func(value *ERABInformationListItemExtIEsValue) (*s00.TransportLayerAddress, bool) {
			return value.AsSourceTransportLayerAddress()
		}}
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
		decode: func(data []byte, options aper.DecodeState) (SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero ERABInformationListItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty SecurityIndication
				return empty, runtime.WrapDecodePath(err, "SecurityIndication")
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty SecurityIndication
				return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SecurityIndication, options aper.DecodeState) (SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SecurityIndication) ERABInformationListItemExtIEsValue {
		return ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}
	}, get: func(value *ERABInformationListItemExtIEsValue) (*SecurityIndication, bool) {
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
func (t ERABInformationListItemExtIETable) SourceNodeTransportLayerAddress() ERABInformationListItemExtIEsTransportLayerAddressExtBinding {
	return ERABInformationListItemExtIEsTransportLayerAddressExtBinding{info: t.infoSourceNodeTransportLayerAddress(), codec: func() s02.TransportLayerAddressValueCodec {
		sealed := s02.TransportLayerAddressValueCodec{}
		*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
		*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
			var zero ERABInformationListItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(340), raw)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, runtime.WrapDecodePath(err, "TransportLayerAddress")
			}
			value, ok := decoded.AsSourceNodeTransportLayerAddress()
			if !ok {
				var empty s00.TransportLayerAddress
				return empty, fmt.Errorf("binding E-RABInformationListItem-ExtIEs.id-SourceNodeTransportLayerAddress: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(340), rowSourceNodeTransportLayerAddress: &value}).encodeFresh(fresh, budget)
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
			s08.BridgeCompareS1APTransportLayerAddress(&v, &s)
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
	}(),
		inject: func(value s00.TransportLayerAddress) ERABInformationListItemExtIEsValue {
			return ERABInformationListItemExtIEsValue{id: s00.ProtocolIEID(340), rowSourceNodeTransportLayerAddress: &value}
		}, get: func(value *ERABInformationListItemExtIEsValue) (*s00.TransportLayerAddress, bool) {
			return value.AsSourceNodeTransportLayerAddress()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABInformationListItemExtIETable.
func (t ERABInformationListItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABInformationListItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(317):
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DAPSRequestInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(328):
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SourceTransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(332):
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(340):
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SourceNodeTransportLayerAddress requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABInformationListItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABInformationListItemExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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
func (t ERABToBeSetupItemBearerSUReqExtIETable) CorrelationID() ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding {
	return ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding{info: t.infoCorrelationID(), codec: func() s00.CorrelationIDValueCodec {
		sealed := s00.CorrelationIDValueCodec{}
		*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
		*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CorrelationID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CorrelationID")
			var zero ERABToBeSetupItemBearerSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(156), raw)
			if err != nil {
				var empty s00.CorrelationID
				return empty, runtime.WrapDecodePath(err, "CorrelationID")
			}
			value, ok := decoded.AsCorrelationID()
			if !ok {
				var empty s00.CorrelationID
				return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-Correlation-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(156), rowCorrelationID: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.CorrelationID) ERABToBeSetupItemBearerSUReqExtIEsValue {
			return ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(156), rowCorrelationID: &value}
		}, get: func(value *ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsCorrelationID()
		}}
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoSIPTOCorrelationID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(183), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Correlation-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-SIPTO-Correlation-ID"}}}
}

// SIPTOCorrelationID returns the typed binding for the SIPTOCorrelationID row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) SIPTOCorrelationID() ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding {
	return ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding{info: t.infoSIPTOCorrelationID(), codec: func() s00.CorrelationIDValueCodec {
		sealed := s00.CorrelationIDValueCodec{}
		*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
		*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CorrelationID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CorrelationID")
			var zero ERABToBeSetupItemBearerSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(183), raw)
			if err != nil {
				var empty s00.CorrelationID
				return empty, runtime.WrapDecodePath(err, "CorrelationID")
			}
			value, ok := decoded.AsSIPTOCorrelationID()
			if !ok {
				var empty s00.CorrelationID
				return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-SIPTO-Correlation-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(183), rowSIPTOCorrelationID: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.CorrelationID) ERABToBeSetupItemBearerSUReqExtIEsValue {
			return ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(183), rowSIPTOCorrelationID: &value}
		}, get: func(value *ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsSIPTOCorrelationID()
		}}
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoBearerType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(233), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BearerType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-BearerType"}}}
}

// BearerType returns the typed binding for the BearerType row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) BearerType() ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding {
	return ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding{info: t.infoBearerType(), codec: func() s00.BearerTypeValueCodec {
		sealed := s00.BearerTypeValueCodec{}
		*s00.BridgeBearerTypeValueCodecFieldPath(&sealed) = "BearerType"
		*s00.BridgeBearerTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BearerType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.BearerType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearerType")
			var zero ERABToBeSetupItemBearerSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(233), raw)
			if err != nil {
				var empty s00.BearerType
				return empty, runtime.WrapDecodePath(err, "BearerType")
			}
			value, ok := decoded.AsBearerType()
			if !ok {
				var empty s00.BearerType
				return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-BearerType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeBearerTypeValueCodecFieldEncode(&sealed) = func(value s00.BearerType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(233), rowBearerType: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.BearerType) ERABToBeSetupItemBearerSUReqExtIEsValue {
			return ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(233), rowBearerType: &value}
		}, get: func(value *ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.BearerType, bool) {
			return value.AsBearerType()
		}}
}
func (ERABToBeSetupItemBearerSUReqExtIETable) infoEthernetType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemBearerSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(305), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Ethernet-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs", Row: "id-Ethernet-Type"}}}
}

// EthernetType returns the typed binding for the EthernetType row of ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) EthernetType() ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding {
	return ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding{info: t.infoEthernetType(), codec: func() s00.EthernetTypeValueCodec {
		sealed := s00.EthernetTypeValueCodec{}
		*s00.BridgeEthernetTypeValueCodecFieldPath(&sealed) = "EthernetType"
		*s00.BridgeEthernetTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EthernetType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EthernetType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EthernetType")
			var zero ERABToBeSetupItemBearerSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(305), raw)
			if err != nil {
				var empty s00.EthernetType
				return empty, runtime.WrapDecodePath(err, "EthernetType")
			}
			value, ok := decoded.AsEthernetType()
			if !ok {
				var empty s00.EthernetType
				return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-Ethernet-Type: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEthernetTypeValueCodecFieldEncode(&sealed) = func(value s00.EthernetType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(305), rowEthernetType: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.EthernetType) ERABToBeSetupItemBearerSUReqExtIEsValue {
			return ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(305), rowEthernetType: &value}
		}, get: func(value *ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.EthernetType, bool) {
			return value.AsEthernetType()
		}}
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
		decode: func(data []byte, options aper.DecodeState) (SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero ERABToBeSetupItemBearerSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty SecurityIndication
				return empty, runtime.WrapDecodePath(err, "SecurityIndication")
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSetupItemBearerSUReqExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SecurityIndication, options aper.DecodeState) (SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SecurityIndication) ERABToBeSetupItemBearerSUReqExtIEsValue {
		return ERABToBeSetupItemBearerSUReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}
	}, get: func(value *ERABToBeSetupItemBearerSUReqExtIEsValue) (*SecurityIndication, bool) {
		return value.AsSecurityIndication()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSetupItemBearerSUReqExtIETable.
func (t ERABToBeSetupItemBearerSUReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(156):
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(183):
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SIPTO-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(233):
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-BearerType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(305):
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Ethernet-Type requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(332):
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABToBeSetupItemBearerSUReqExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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
func (t ERABToBeSetupItemCtxtSUReqExtIETable) CorrelationID() ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding {
	return ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding{info: t.infoCorrelationID(), codec: func() s00.CorrelationIDValueCodec {
		sealed := s00.CorrelationIDValueCodec{}
		*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
		*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CorrelationID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CorrelationID")
			var zero ERABToBeSetupItemCtxtSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(156), raw)
			if err != nil {
				var empty s00.CorrelationID
				return empty, runtime.WrapDecodePath(err, "CorrelationID")
			}
			value, ok := decoded.AsCorrelationID()
			if !ok {
				var empty s00.CorrelationID
				return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-Correlation-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(156), rowCorrelationID: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.CorrelationID) ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(156), rowCorrelationID: &value}
		}, get: func(value *ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsCorrelationID()
		}}
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoSIPTOCorrelationID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(183), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Correlation-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-SIPTO-Correlation-ID"}}}
}

// SIPTOCorrelationID returns the typed binding for the SIPTOCorrelationID row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) SIPTOCorrelationID() ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding {
	return ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding{info: t.infoSIPTOCorrelationID(), codec: func() s00.CorrelationIDValueCodec {
		sealed := s00.CorrelationIDValueCodec{}
		*s00.BridgeCorrelationIDValueCodecFieldPath(&sealed) = "CorrelationID"
		*s00.BridgeCorrelationIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CorrelationID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CorrelationID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CorrelationID")
			var zero ERABToBeSetupItemCtxtSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(183), raw)
			if err != nil {
				var empty s00.CorrelationID
				return empty, runtime.WrapDecodePath(err, "CorrelationID")
			}
			value, ok := decoded.AsSIPTOCorrelationID()
			if !ok {
				var empty s00.CorrelationID
				return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-SIPTO-Correlation-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCorrelationIDValueCodecFieldEncode(&sealed) = func(value s00.CorrelationID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(183), rowSIPTOCorrelationID: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.CorrelationID) ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(183), rowSIPTOCorrelationID: &value}
		}, get: func(value *ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.CorrelationID, bool) {
			return value.AsSIPTOCorrelationID()
		}}
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoBearerType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(233), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BearerType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-BearerType"}}}
}

// BearerType returns the typed binding for the BearerType row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) BearerType() ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding {
	return ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding{info: t.infoBearerType(), codec: func() s00.BearerTypeValueCodec {
		sealed := s00.BearerTypeValueCodec{}
		*s00.BridgeBearerTypeValueCodecFieldPath(&sealed) = "BearerType"
		*s00.BridgeBearerTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BearerType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.BearerType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearerType")
			var zero ERABToBeSetupItemCtxtSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(233), raw)
			if err != nil {
				var empty s00.BearerType
				return empty, runtime.WrapDecodePath(err, "BearerType")
			}
			value, ok := decoded.AsBearerType()
			if !ok {
				var empty s00.BearerType
				return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-BearerType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeBearerTypeValueCodecFieldEncode(&sealed) = func(value s00.BearerType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(233), rowBearerType: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.BearerType) ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(233), rowBearerType: &value}
		}, get: func(value *ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.BearerType, bool) {
			return value.AsBearerType()
		}}
}
func (ERABToBeSetupItemCtxtSUReqExtIETable) infoEthernetType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeSetupItemCtxtSUReqExtIEs().ID(), ID: s00.ProtocolExtensionID(305), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Ethernet-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs", Row: "id-Ethernet-Type"}}}
}

// EthernetType returns the typed binding for the EthernetType row of ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) EthernetType() ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding {
	return ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding{info: t.infoEthernetType(), codec: func() s00.EthernetTypeValueCodec {
		sealed := s00.EthernetTypeValueCodec{}
		*s00.BridgeEthernetTypeValueCodecFieldPath(&sealed) = "EthernetType"
		*s00.BridgeEthernetTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EthernetType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EthernetType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EthernetType")
			var zero ERABToBeSetupItemCtxtSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(305), raw)
			if err != nil {
				var empty s00.EthernetType
				return empty, runtime.WrapDecodePath(err, "EthernetType")
			}
			value, ok := decoded.AsEthernetType()
			if !ok {
				var empty s00.EthernetType
				return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-Ethernet-Type: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEthernetTypeValueCodecFieldEncode(&sealed) = func(value s00.EthernetType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(305), rowEthernetType: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.EthernetType) ERABToBeSetupItemCtxtSUReqExtIEsValue {
			return ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(305), rowEthernetType: &value}
		}, get: func(value *ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.EthernetType, bool) {
			return value.AsEthernetType()
		}}
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
		decode: func(data []byte, options aper.DecodeState) (SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero ERABToBeSetupItemCtxtSUReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty SecurityIndication
				return empty, runtime.WrapDecodePath(err, "SecurityIndication")
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSetupItemCtxtSUReqExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SecurityIndication, options aper.DecodeState) (SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SecurityIndication) ERABToBeSetupItemCtxtSUReqExtIEsValue {
		return ERABToBeSetupItemCtxtSUReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}
	}, get: func(value *ERABToBeSetupItemCtxtSUReqExtIEsValue) (*SecurityIndication, bool) {
		return value.AsSecurityIndication()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSetupItemCtxtSUReqExtIETable.
func (t ERABToBeSetupItemCtxtSUReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(156):
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(183):
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SIPTO-Correlation-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(233):
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-BearerType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(305):
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Ethernet-Type requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(332):
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SecurityIndication requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABToBeSetupItemCtxtSUReqExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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
				return empty, runtime.WrapDecodePath(err, "DataForwardingNotPossible")
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
				return empty, runtime.WrapDecodePath(err, "BearerType")
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
				return empty, runtime.WrapDecodePath(err, "EthernetType")
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
		decode: func(data []byte, options aper.DecodeState) (SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero ERABToBeSetupItemHOReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty SecurityIndication
				return empty, runtime.WrapDecodePath(err, "SecurityIndication")
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSetupItemHOReq-ExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SecurityIndication, options aper.DecodeState) (SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SecurityIndication) ERABToBeSetupItemHOReqExtIEsValue {
		return ERABToBeSetupItemHOReqExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}
	}, get: func(value *ERABToBeSetupItemHOReqExtIEsValue) (*SecurityIndication, bool) {
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
		decode: func(data []byte, options aper.DecodeState) (SecurityIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SecurityIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityIndication")
			var zero ERABToBeSwitchedDLItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(332), raw)
			if err != nil {
				var empty SecurityIndication
				return empty, runtime.WrapDecodePath(err, "SecurityIndication")
			}
			value, ok := decoded.AsSecurityIndication()
			if !ok {
				var empty SecurityIndication
				return empty, fmt.Errorf("binding E-RABToBeSwitchedDLItem-ExtIEs.id-SecurityIndication: no selected value")
			}
			return *value, nil
		},
		encode: func(value SecurityIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSwitchedDLItemExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SecurityIndication, options aper.DecodeState) (SecurityIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSecurityIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v SecurityIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecurityIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SecurityIndication) ERABToBeSwitchedDLItemExtIEsValue {
		return ERABToBeSwitchedDLItemExtIEsValue{id: s00.ProtocolIEID(332), rowSecurityIndication: &value}
	}, get: func(value *ERABToBeSwitchedDLItemExtIEsValue) (*SecurityIndication, bool) {
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
				return empty, runtime.WrapDecodePath(err, "ERABToBeUpdatedItem")
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

type UEContextSuspendResponseIETable struct{}

func UEContextSuspendResponseIEs() UEContextSuspendResponseIETable {
	return UEContextSuspendResponseIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextSuspendResponseIETable.
func (UEContextSuspendResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextSuspendResponseIETable.
func (UEContextSuspendResponseIETable) Table() s00.UEContextSuspendResponseIEValueIETable {
	return func() s00.UEContextSuspendResponseIEValueIETable {
		sealed := s00.UEContextSuspendResponseIEValueIETable{}
		*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextSuspendResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextSuspendResponseIETable.
func (t UEContextSuspendResponseIETable) MMEUES1APID() s36.UEContextSuspendResponseMMEUES1APIDIEBinding {
	return func() s36.UEContextSuspendResponseMMEUES1APIDIEBinding {
		sealed := s36.UEContextSuspendResponseMMEUES1APIDIEBinding{}
		*s36.BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s36.BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s36.UEContextSuspendResponseIEValue
				decoded, err := s36.BridgeUEContextSuspendResponseIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s36.BridgeUEContextSuspendResponseIEValueMethodEncodeFresh((func() s36.UEContextSuspendResponseIEValue {
					sealed := s36.UEContextSuspendResponseIEValue{}
					*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s36.BridgeUEContextSuspendResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s36.BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s36.UEContextSuspendResponseIEValue {
			return func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s36.BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s36.UEContextSuspendResponseIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (UEContextSuspendResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextSuspendResponseIETable.
func (t UEContextSuspendResponseIETable) ENBUES1APID() s36.UEContextSuspendResponseENBUES1APIDIEBinding {
	return func() s36.UEContextSuspendResponseENBUES1APIDIEBinding {
		sealed := s36.UEContextSuspendResponseENBUES1APIDIEBinding{}
		*s36.BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s36.BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s36.UEContextSuspendResponseIEValue
				decoded, err := s36.BridgeUEContextSuspendResponseIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s36.BridgeUEContextSuspendResponseIEValueMethodEncodeFresh((func() s36.UEContextSuspendResponseIEValue {
					sealed := s36.UEContextSuspendResponseIEValue{}
					*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s36.BridgeUEContextSuspendResponseIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s36.BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s36.UEContextSuspendResponseIEValue {
			return func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s36.BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s36.UEContextSuspendResponseIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (UEContextSuspendResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of UEContextSuspendResponseIETable.
func (t UEContextSuspendResponseIETable) CriticalityDiagnostics() s36.UEContextSuspendResponseCriticalityDiagnosticsIEBinding {
	return func() s36.UEContextSuspendResponseCriticalityDiagnosticsIEBinding {
		sealed := s36.UEContextSuspendResponseCriticalityDiagnosticsIEBinding{}
		*s36.BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s36.BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s26.CriticalityDiagnosticsValueCodec {
			sealed := s26.CriticalityDiagnosticsValueCodec{}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s36.UEContextSuspendResponseIEValue
				decoded, err := s36.BridgeUEContextSuspendResponseIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s26.CriticalityDiagnostics
					return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s36.BridgeUEContextSuspendResponseIEValueMethodEncodeFresh((func() s36.UEContextSuspendResponseIEValue {
					sealed := s36.UEContextSuspendResponseIEValue{}
					*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s36.BridgeUEContextSuspendResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s36.BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s26.CriticalityDiagnostics) s36.UEContextSuspendResponseIEValue {
			return func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s36.BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s36.UEContextSuspendResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (UEContextSuspendResponseIETable) infoSecurityContext() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(40), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityContext"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-SecurityContext"}}}
}

// SecurityContext returns the typed binding for the SecurityContext row of UEContextSuspendResponseIETable.
func (t UEContextSuspendResponseIETable) SecurityContext() s36.UEContextSuspendResponseSecurityContextIEBinding {
	return func() s36.UEContextSuspendResponseSecurityContextIEBinding {
		sealed := s36.UEContextSuspendResponseSecurityContextIEBinding{}
		*s36.BridgeUEContextSuspendResponseSecurityContextIEBindingFieldInfo(&sealed) = t.infoSecurityContext()
		*s36.BridgeUEContextSuspendResponseSecurityContextIEBindingFieldCodec(&sealed) = func() s36.SecurityContextValueCodec {
			sealed := s36.SecurityContextValueCodec{}
			*s36.BridgeSecurityContextValueCodecFieldPath(&sealed) = "SecurityContext"
			*s36.BridgeSecurityContextValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecurityContext, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecurityContext
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecurityContext")
				var zero s36.UEContextSuspendResponseIEValue
				decoded, err := s36.BridgeUEContextSuspendResponseIEValueMethodDecode(zero, s00.ProtocolIEID(40), raw)
				if err != nil {
					var empty s36.SecurityContext
					return empty, runtime.WrapDecodePath(err, "SecurityContext")
				}
				value, ok := decoded.AsSecurityContext()
				if !ok {
					var empty s36.SecurityContext
					return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-SecurityContext: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecurityContextValueCodecFieldEncode(&sealed) = func(value s36.SecurityContext, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s36.BridgeUEContextSuspendResponseIEValueMethodEncodeFresh((func() s36.UEContextSuspendResponseIEValue {
					sealed := s36.UEContextSuspendResponseIEValue{}
					*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
					*s36.BridgeUEContextSuspendResponseIEValueFieldRowSecurityContext(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecurityContextValueCodecFieldCapture(&sealed) = func(v s36.SecurityContext, options aper.DecodeState) (s36.SecurityContext, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecurityContext(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecurityContextValueCodecFieldCompare(&sealed) = func(v s36.SecurityContext, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecurityContext(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s36.BridgeSecurityContextValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityContext"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s36.BridgeUEContextSuspendResponseSecurityContextIEBindingFieldInject(&sealed) = func(value s36.SecurityContext) s36.UEContextSuspendResponseIEValue {
			return func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowSecurityContext(&sealed) = &value
				return sealed
			}()
		}
		*s36.BridgeUEContextSuspendResponseSecurityContextIEBindingFieldGet(&sealed) = func(value *s36.UEContextSuspendResponseIEValue) (*s36.SecurityContext, bool) {
			return value.AsSecurityContext()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextSuspendResponseIETable.
func (t UEContextSuspendResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s36.UEContextSuspendResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s36.UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s36.UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s36.UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s36.UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(40):
		return s36.UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityContext requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s36.UEContextSuspendResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s36.UEContextSuspendResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return s36.UEContextSuspendResponseIEField{Id: id, Criticality: criticality, Value: func() s36.UEContextSuspendResponseIEValue {
			sealed := s36.UEContextSuspendResponseIEValue{}
			*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = id
			*s36.BridgeUEContextSuspendResponseIEValueFieldOpaque(&sealed) = opaque
			*s36.BridgeUEContextSuspendResponseIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
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
func DAPSRequestInfoCodec() s17.DAPSRequestInfoValueCodec {
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
func BridgeERABInformationListIEFieldMethodMarshalAPERTo(v *ERABInformationListIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABInformationListIEFieldMethodUnmarshalAPERFrom(v *ERABInformationListIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeERABInformationListIEValueFieldRowERABInformationListItem(v *ERABInformationListIEValue) **ERABInformationListItem {
	return &v.rowERABInformationListItem
}
func BridgeERABInformationListItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABInformationListItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABInformationListItemExtIEsValueFieldId(v *ERABInformationListItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABInformationListItemExtIEsValueFieldIsOpaque(v *ERABInformationListItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABInformationListItemExtIEsValueFieldOpaque(v *ERABInformationListItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABInformationListItemExtIEsValueFieldRowDAPSRequestInfo(v *ERABInformationListItemExtIEsValue) **s17.DAPSRequestInfo {
	return &v.rowDAPSRequestInfo
}
func BridgeERABInformationListItemExtIEsValueFieldRowSecurityIndication(v *ERABInformationListItemExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABInformationListItemExtIEsValueFieldRowSourceNodeTransportLayerAddress(v *ERABInformationListItemExtIEsValue) **s00.TransportLayerAddress {
	return &v.rowSourceNodeTransportLayerAddress
}
func BridgeERABInformationListItemExtIEsValueFieldRowSourceTransportLayerAddress(v *ERABInformationListItemExtIEsValue) **s00.TransportLayerAddress {
	return &v.rowSourceTransportLayerAddress
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
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldIsOpaque(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldOpaque(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowBearerType(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.BearerType {
	return &v.rowBearerType
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowCorrelationID(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowCorrelationID
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowEthernetType(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.EthernetType {
	return &v.rowEthernetType
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSIPTOCorrelationID(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowSIPTOCorrelationID
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSecurityIndication(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodMatchesID(v ERABToBeSetupItemBearerSUReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodRule(v ERABToBeSetupItemBearerSUReqExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSetupItemBearerSUReqFieldPerPadding(v *ERABToBeSetupItemBearerSUReq) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABToBeSetupItemBearerSUReqFieldReceived(v *ERABToBeSetupItemBearerSUReq) *bool {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqFieldReceivedBytes(v *ERABToBeSetupItemBearerSUReq) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSetupItemBearerSUReqFieldReceivedLocation(v *ERABToBeSetupItemBearerSUReq) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSetupItemBearerSUReqMethodMarshalAPERBudget(v *ERABToBeSetupItemBearerSUReq, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqMethodUnmarshalAPERFrom(v *ERABToBeSetupItemBearerSUReq, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldIsOpaque(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldOpaque(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowBearerType(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.BearerType {
	return &v.rowBearerType
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowCorrelationID(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowCorrelationID
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowEthernetType(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.EthernetType {
	return &v.rowEthernetType
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSIPTOCorrelationID(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowSIPTOCorrelationID
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSecurityIndication(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodCaptureSemantics(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 aper.SemanticCapture) ERABToBeSetupItemCtxtSUReqExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodCompareSemantics(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodMatchesID(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodRule(v ERABToBeSetupItemCtxtSUReqExtIEsValue) aper.SourceRule {
	return v.rule()
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
func BridgeERABToBeSetupItemHOReqExtIEsExtFieldFieldReplay(v *ERABToBeSetupItemHOReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
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
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(v *ERABToBeSetupItemHOReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldIsOpaque(v *ERABToBeSetupItemHOReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldOpaque(v *ERABToBeSetupItemHOReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
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
func BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowSecurityIndication(v *ERABToBeSetupItemHOReqExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodCaptureSemantics(v ERABToBeSetupItemHOReqExtIEsValue, a0 aper.SemanticCapture) ERABToBeSetupItemHOReqExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodCompareSemantics(v ERABToBeSetupItemHOReqExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodMatchesID(v ERABToBeSetupItemHOReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemHOReqExtIEsValueMethodRule(v ERABToBeSetupItemHOReqExtIEsValue) aper.SourceRule {
	return v.rule()
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
func BridgeERABToBeSwitchedDLItemExtIEsExtFieldFieldReplay(v *ERABToBeSwitchedDLItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
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
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldId(v *ERABToBeSwitchedDLItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldIsOpaque(v *ERABToBeSwitchedDLItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldOpaque(v *ERABToBeSwitchedDLItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSwitchedDLItemExtIEsValueFieldRowSecurityIndication(v *ERABToBeSwitchedDLItemExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodCaptureSemantics(v ERABToBeSwitchedDLItemExtIEsValue, a0 aper.SemanticCapture) ERABToBeSwitchedDLItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodCompareSemantics(v ERABToBeSwitchedDLItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodMatchesID(v ERABToBeSwitchedDLItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSwitchedDLItemExtIEsValueMethodRule(v ERABToBeSwitchedDLItemExtIEsValue) aper.SourceRule {
	return v.rule()
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
func BridgeERABToBeUpdatedItemIEFieldFieldReplay(v *ERABToBeUpdatedItemIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeERABToBeUpdatedItemIEValueFieldId(v *ERABToBeUpdatedItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeUpdatedItemIEValueFieldIsOpaque(v *ERABToBeUpdatedItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeUpdatedItemIEValueFieldOpaque(v *ERABToBeUpdatedItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
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
func BridgeERABToBeUpdatedItemIEValueMethodMatchesID(v ERABToBeUpdatedItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeUpdatedItemIEValueMethodRule(v ERABToBeUpdatedItemIEValue) aper.SourceRule {
	return v.rule()
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

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABInformationListIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 78:
		if value, ok := v.AsERABInformationListItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABInformationListItemExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 317:
		if value, ok := v.AsDAPSRequestInfo(); ok {
			return value, true
		}
	case 328:
		if value, ok := v.AsSourceTransportLayerAddress(); ok {
			return value, true
		}
	case 332:
		if value, ok := v.AsSecurityIndication(); ok {
			return value, true
		}
	case 340:
		if value, ok := v.AsSourceNodeTransportLayerAddress(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 156:
		if value, ok := v.AsCorrelationID(); ok {
			return value, true
		}
	case 183:
		if value, ok := v.AsSIPTOCorrelationID(); ok {
			return value, true
		}
	case 233:
		if value, ok := v.AsBearerType(); ok {
			return value, true
		}
	case 305:
		if value, ok := v.AsEthernetType(); ok {
			return value, true
		}
	case 332:
		if value, ok := v.AsSecurityIndication(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 156:
		if value, ok := v.AsCorrelationID(); ok {
			return value, true
		}
	case 183:
		if value, ok := v.AsSIPTOCorrelationID(); ok {
			return value, true
		}
	case 233:
		if value, ok := v.AsBearerType(); ok {
			return value, true
		}
	case 305:
		if value, ok := v.AsEthernetType(); ok {
			return value, true
		}
	case 332:
		if value, ok := v.AsSecurityIndication(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABToBeSetupItemHOReqExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 143:
		if value, ok := v.AsDataForwardingNotPossible(); ok {
			return value, true
		}
	case 233:
		if value, ok := v.AsBearerType(); ok {
			return value, true
		}
	case 305:
		if value, ok := v.AsEthernetType(); ok {
			return value, true
		}
	case 332:
		if value, ok := v.AsSecurityIndication(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABToBeSwitchedDLItemExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 332:
		if value, ok := v.AsSecurityIndication(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABToBeUpdatedItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 342:
		if value, ok := v.AsERABToBeUpdatedItem(); ok {
			return value, true
		}
	}
	return nil, false
}
