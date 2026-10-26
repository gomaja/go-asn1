// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s10 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s10

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s04 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// EmergencyAreaIDBroadcastItemExtIEsExtContainer is ProtocolExtensionContainer {{EmergencyAreaID-Broadcast-Item-ExtIEs}} of TS 36.413: a list of EmergencyAreaIDBroadcastItemExtIEsExtField values.
type EmergencyAreaIDBroadcastItemExtIEsExtContainer []EmergencyAreaIDBroadcastItemExtIEsExtField

// EmergencyAreaIDCancelledItemExtIEsExtContainer is ProtocolExtensionContainer {{EmergencyAreaID-Cancelled-Item-ExtIEs}} of TS 36.413: a list of EmergencyAreaIDCancelledItemExtIEsExtField values.
type EmergencyAreaIDCancelledItemExtIEsExtContainer []EmergencyAreaIDCancelledItemExtIEsExtField

// ENDCTransferTypeRequestExtIEsExtContainer is ProtocolExtensionContainer {{EN-DCTransferTypeRequest-ExtIEs}} of TS 36.413: a list of ENDCTransferTypeRequestExtIEsExtField values.
type ENDCTransferTypeRequestExtIEsExtContainer []ENDCTransferTypeRequestExtIEsExtField

// ERABItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABItem-ExtIEs}} of TS 36.413: a list of ERABItemExtIEsExtField values.
type ERABItemExtIEsExtContainer []ERABItemExtIEsExtField

// ERABQoSParametersExtIEsExtContainer is ProtocolExtensionContainer {{E-RABQoSParameters-ExtIEs}} of TS 36.413: a list of ERABQoSParametersExtIEsExtField values.
type ERABQoSParametersExtIEsExtContainer []ERABQoSParametersExtIEsExtField

// ERABSecurityResultItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABSecurityResultItem-ExtIEs}} of TS 36.413: a list of ERABSecurityResultItemExtIEsExtField values.
type ERABSecurityResultItemExtIEsExtContainer []ERABSecurityResultItemExtIEsExtField

// ERABUsageReportItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABUsageReportItem-ExtIEs}} of TS 36.413: a list of ERABUsageReportItemExtIEsExtField values.
type ERABUsageReportItemExtIEsExtContainer []ERABUsageReportItemExtIEsExtField

// EUTRANCGIExtIEsExtContainer is ProtocolExtensionContainer {{EUTRAN-CGI-ExtIEs}} of TS 36.413: a list of EUTRANCGIExtIEsExtField values.
type EUTRANCGIExtIEsExtContainer []EUTRANCGIExtIEsExtField

// EventL1LoggedMDTConfigExtIEsExtContainer is ProtocolExtensionContainer {{EventL1LoggedMDTConfig-ExtIEs}} of TS 36.413: a list of EventL1LoggedMDTConfigExtIEsExtField values.
type EventL1LoggedMDTConfigExtIEsExtContainer []EventL1LoggedMDTConfigExtIEsExtField

// EventTriggerExtIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{EventTrigger-ExtIEs}} of TS 36.413: a single information element field.
type EventTriggerExtIEValueProtocolIESingleContainer = EventTriggerExtIEField

// ExpectedUEBehaviourExtIEsExtContainer is ProtocolExtensionContainer {{ExpectedUEBehaviour-ExtIEs}} of TS 36.413: a list of ExpectedUEBehaviourExtIEsExtField values.
type ExpectedUEBehaviourExtIEsExtContainer []ExpectedUEBehaviourExtIEsExtField

// ExpectedUEActivityBehaviourExtIEsExtContainer is ProtocolExtensionContainer {{ExpectedUEActivityBehaviour-ExtIEs}} of TS 36.413: a list of ExpectedUEActivityBehaviourExtIEsExtField values.
type ExpectedUEActivityBehaviourExtIEsExtContainer []ExpectedUEActivityBehaviourExtIEsExtField

// FiveGSTAIExtIEsExtContainer is ProtocolExtensionContainer {{FiveGSTAI-ExtIEs}} of TS 36.413: a list of FiveGSTAIExtIEsExtField values.
type FiveGSTAIExtIEsExtContainer []FiveGSTAIExtIEsExtField

// ForbiddenTAsItemExtIEsExtContainer is ProtocolExtensionContainer {{ForbiddenTAs-Item-ExtIEs}} of TS 36.413: a list of ForbiddenTAsItemExtIEsExtField values.
type ForbiddenTAsItemExtIEsExtContainer []ForbiddenTAsItemExtIEsExtField

// ForbiddenLAsItemExtIEsExtContainer is ProtocolExtensionContainer {{ForbiddenLAs-Item-ExtIEs}} of TS 36.413: a list of ForbiddenLAsItemExtIEsExtField values.
type ForbiddenLAsItemExtIEsExtContainer []ForbiddenLAsItemExtIEsExtField

// EmergencyAreaIDBroadcastItemExtIEsExtField is ProtocolExtensionField {{EmergencyAreaID-Broadcast-Item-ExtIEs}} of TS 36.413: an extension field.
type EmergencyAreaIDBroadcastItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.EmergencyAreaIDBroadcastItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDBroadcastItemExtIEsExtField) WithoutReplay() EmergencyAreaIDBroadcastItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EmergencyAreaIDBroadcastItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EmergencyAreaIDBroadcastItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EmergencyAreaIDBroadcastItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDBroadcastItemExtIEsExtField{}
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
	var zero s04.EmergencyAreaIDBroadcastItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// EmergencyAreaIDCancelledItemExtIEsExtField is ProtocolExtensionField {{EmergencyAreaID-Cancelled-Item-ExtIEs}} of TS 36.413: an extension field.
type EmergencyAreaIDCancelledItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.EmergencyAreaIDCancelledItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledItemExtIEsExtField) WithoutReplay() EmergencyAreaIDCancelledItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EmergencyAreaIDCancelledItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EmergencyAreaIDCancelledItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EmergencyAreaIDCancelledItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDCancelledItemExtIEsExtField{}
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
	var zero s04.EmergencyAreaIDCancelledItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCTransferTypeRequestExtIEsExtField is ProtocolExtensionField {{EN-DCTransferTypeRequest-ExtIEs}} of TS 36.413: an extension field.
type ENDCTransferTypeRequestExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ENDCTransferTypeRequestExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeRequestExtIEsExtField) WithoutReplay() ENDCTransferTypeRequestExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCTransferTypeRequestExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCTransferTypeRequestExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeENDCTransferTypeRequestExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCTransferTypeRequestExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCTransferTypeRequestExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCTransferTypeRequestExtIEsExtField{}
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
	var zero s04.ENDCTransferTypeRequestExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCTransferTypeRequestExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCTransferTypeRequestExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeENDCTransferTypeRequestExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABItemExtIEsExtField is ProtocolExtensionField {{E-RABItem-ExtIEs}} of TS 36.413: an extension field.
type ERABItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemExtIEsExtField) WithoutReplay() ERABItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABItemExtIEsExtField{}
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
	var zero s04.ERABItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABQoSParametersExtIEsExtField is ProtocolExtensionField {{E-RABQoSParameters-ExtIEs}} of TS 36.413: an extension field.
type ERABQoSParametersExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABQoSParametersExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABQoSParametersExtIEsExtField) WithoutReplay() ERABQoSParametersExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABQoSParametersExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABQoSParametersExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABQoSParametersExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABQoSParametersExtIEsExtField{}
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
	var zero ERABQoSParametersExtIEsValue

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

// ERABSecurityResultItemExtIEsExtField is ProtocolExtensionField {{E-RABSecurityResultItem-ExtIEs}} of TS 36.413: an extension field.
type ERABSecurityResultItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABSecurityResultItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultItemExtIEsExtField) WithoutReplay() ERABSecurityResultItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSecurityResultItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSecurityResultItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABSecurityResultItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABSecurityResultItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABSecurityResultItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSecurityResultItemExtIEsExtField{}
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
	var zero s04.ERABSecurityResultItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABSecurityResultItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABSecurityResultItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABSecurityResultItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABUsageReportItemExtIEsExtField is ProtocolExtensionField {{E-RABUsageReportItem-ExtIEs}} of TS 36.413: an extension field.
type ERABUsageReportItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABUsageReportItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemExtIEsExtField) WithoutReplay() ERABUsageReportItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABUsageReportItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABUsageReportItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABUsageReportItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABUsageReportItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABUsageReportItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABUsageReportItemExtIEsExtField{}
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
	var zero s04.ERABUsageReportItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABUsageReportItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABUsageReportItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABUsageReportItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// EUTRANCGIExtIEsExtField is ProtocolExtensionField {{EUTRAN-CGI-ExtIEs}} of TS 36.413: an extension field.
type EUTRANCGIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.EUTRANCGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EUTRANCGIExtIEsExtField) WithoutReplay() EUTRANCGIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EUTRANCGIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EUTRANCGIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEUTRANCGIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEUTRANCGIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EUTRANCGIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EUTRANCGIExtIEsExtField{}
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
	var zero s04.EUTRANCGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEUTRANCGIExtIEsValueMethodReason(zero, v.Id), s04.BridgeEUTRANCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeEUTRANCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// EventL1LoggedMDTConfigExtIEsExtField is ProtocolExtensionField {{EventL1LoggedMDTConfig-ExtIEs}} of TS 36.413: an extension field.
type EventL1LoggedMDTConfigExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.EventL1LoggedMDTConfigExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventL1LoggedMDTConfigExtIEsExtField) WithoutReplay() EventL1LoggedMDTConfigExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EventL1LoggedMDTConfigExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EventL1LoggedMDTConfigExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EventL1LoggedMDTConfigExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventL1LoggedMDTConfigExtIEsExtField{}
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
	var zero s04.EventL1LoggedMDTConfigExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodReason(zero, v.Id), s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ExpectedUEBehaviourExtIEsExtField is ProtocolExtensionField {{ExpectedUEBehaviour-ExtIEs}} of TS 36.413: an extension field.
type ExpectedUEBehaviourExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.ExpectedUEBehaviourExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEBehaviourExtIEsExtField) WithoutReplay() ExpectedUEBehaviourExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ExpectedUEBehaviourExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ExpectedUEBehaviourExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeExpectedUEBehaviourExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeExpectedUEBehaviourExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ExpectedUEBehaviourExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ExpectedUEBehaviourExtIEsExtField{}
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
	var zero s05.ExpectedUEBehaviourExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeExpectedUEBehaviourExtIEsValueMethodReason(zero, v.Id), s05.BridgeExpectedUEBehaviourExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeExpectedUEBehaviourExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ExpectedUEActivityBehaviourExtIEsExtField is ProtocolExtensionField {{ExpectedUEActivityBehaviour-ExtIEs}} of TS 36.413: an extension field.
type ExpectedUEActivityBehaviourExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.ExpectedUEActivityBehaviourExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEActivityBehaviourExtIEsExtField) WithoutReplay() ExpectedUEActivityBehaviourExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ExpectedUEActivityBehaviourExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ExpectedUEActivityBehaviourExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ExpectedUEActivityBehaviourExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ExpectedUEActivityBehaviourExtIEsExtField{}
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
	var zero s05.ExpectedUEActivityBehaviourExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodReason(zero, v.Id), s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// FiveGSTAIExtIEsExtField is ProtocolExtensionField {{FiveGSTAI-ExtIEs}} of TS 36.413: an extension field.
type FiveGSTAIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.FiveGSTAIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FiveGSTAIExtIEsExtField) WithoutReplay() FiveGSTAIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *FiveGSTAIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *FiveGSTAIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeFiveGSTAIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeFiveGSTAIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *FiveGSTAIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = FiveGSTAIExtIEsExtField{}
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
	var zero s05.FiveGSTAIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeFiveGSTAIExtIEsValueMethodReason(zero, v.Id), s05.BridgeFiveGSTAIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeFiveGSTAIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ForbiddenTAsItemExtIEsExtField is ProtocolExtensionField {{ForbiddenTAs-Item-ExtIEs}} of TS 36.413: an extension field.
type ForbiddenTAsItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.ForbiddenTAsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenTAsItemExtIEsExtField) WithoutReplay() ForbiddenTAsItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ForbiddenTAsItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ForbiddenTAsItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeForbiddenTAsItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeForbiddenTAsItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ForbiddenTAsItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ForbiddenTAsItemExtIEsExtField{}
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
	var zero s05.ForbiddenTAsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeForbiddenTAsItemExtIEsValueMethodReason(zero, v.Id), s05.BridgeForbiddenTAsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeForbiddenTAsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ForbiddenLAsItemExtIEsExtField is ProtocolExtensionField {{ForbiddenLAs-Item-ExtIEs}} of TS 36.413: an extension field.
type ForbiddenLAsItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.ForbiddenLAsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenLAsItemExtIEsExtField) WithoutReplay() ForbiddenLAsItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ForbiddenLAsItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ForbiddenLAsItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeForbiddenLAsItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeForbiddenLAsItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ForbiddenLAsItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ForbiddenLAsItemExtIEsExtField{}
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
	var zero s05.ForbiddenLAsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeForbiddenLAsItemExtIEsValueMethodReason(zero, v.Id), s05.BridgeForbiddenLAsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeForbiddenLAsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABDataForwardingItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABDataForwardingItem-ExtIEs}} of TS 36.413: a list of ERABDataForwardingItemExtIEsExtField values.
type ERABDataForwardingItemExtIEsExtContainer []ERABDataForwardingItemExtIEsExtField

// ERABAdmittedItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABAdmittedItem-ExtIEs}} of TS 36.413: a list of ERABAdmittedItemExtIEsExtField values.
type ERABAdmittedItemExtIEsExtContainer []ERABAdmittedItemExtIEsExtField

// ERABFailedToSetupItemHOReqAckExtIEsExtContainer is ProtocolExtensionContainer {{E-RABFailedToSetupItemHOReqAckExtIEs}} of TS 36.413: a list of ERABFailedToSetupItemHOReqAckExtIEsExtField values.
type ERABFailedToSetupItemHOReqAckExtIEsExtContainer []ERABFailedToSetupItemHOReqAckExtIEsExtField

// ERABToBeSwitchedULItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeSwitchedULItem-ExtIEs}} of TS 36.413: a list of ERABToBeSwitchedULItemExtIEsExtField values.
type ERABToBeSwitchedULItemExtIEsExtContainer []ERABToBeSwitchedULItemExtIEsExtField

// ERABToBeUpdatedItemExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeUpdatedItem-ExtIEs}} of TS 36.413: a list of ERABToBeUpdatedItemExtIEsExtField values.
type ERABToBeUpdatedItemExtIEsExtContainer []ERABToBeUpdatedItemExtIEsExtField

// ERABSetupItemBearerSUResExtIEsExtContainer is ProtocolExtensionContainer {{E-RABSetupItemBearerSUResExtIEs}} of TS 36.413: a list of ERABSetupItemBearerSUResExtIEsExtField values.
type ERABSetupItemBearerSUResExtIEsExtContainer []ERABSetupItemBearerSUResExtIEsExtField

// ERABModifyItemBearerModResExtIEsExtContainer is ProtocolExtensionContainer {{E-RABModifyItemBearerModResExtIEs}} of TS 36.413: a list of ERABModifyItemBearerModResExtIEsExtField values.
type ERABModifyItemBearerModResExtIEsExtContainer []ERABModifyItemBearerModResExtIEsExtField

// ERABReleaseItemBearerRelCompExtIEsExtContainer is ProtocolExtensionContainer {{E-RABReleaseItemBearerRelCompExtIEs}} of TS 36.413: a list of ERABReleaseItemBearerRelCompExtIEsExtField values.
type ERABReleaseItemBearerRelCompExtIEsExtContainer []ERABReleaseItemBearerRelCompExtIEsExtField

// ERABSetupItemCtxtSUResExtIEsExtContainer is ProtocolExtensionContainer {{E-RABSetupItemCtxtSUResExtIEs}} of TS 36.413: a list of ERABSetupItemCtxtSUResExtIEsExtField values.
type ERABSetupItemCtxtSUResExtIEsExtContainer []ERABSetupItemCtxtSUResExtIEsExtField

// ERABToBeModifiedItemBearerModIndExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeModifiedItemBearerModInd-ExtIEs}} of TS 36.413: a list of ERABToBeModifiedItemBearerModIndExtIEsExtField values.
type ERABToBeModifiedItemBearerModIndExtIEsExtContainer []ERABToBeModifiedItemBearerModIndExtIEsExtField

// ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer is ProtocolExtensionContainer {{E-RABNotToBeModifiedItemBearerModInd-ExtIEs}} of TS 36.413: a list of ERABNotToBeModifiedItemBearerModIndExtIEsExtField values.
type ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer []ERABNotToBeModifiedItemBearerModIndExtIEsExtField

// ERABModifyItemBearerModConfExtIEsExtContainer is ProtocolExtensionContainer {{E-RABModifyItemBearerModConfExtIEs}} of TS 36.413: a list of ERABModifyItemBearerModConfExtIEsExtField values.
type ERABModifyItemBearerModConfExtIEsExtContainer []ERABModifyItemBearerModConfExtIEsExtField

// ERABFailedToResumeItemResumeReqExtIEsExtContainer is ProtocolExtensionContainer {{E-RABFailedToResumeItemResumeReq-ExtIEs}} of TS 36.413: a list of ERABFailedToResumeItemResumeReqExtIEsExtField values.
type ERABFailedToResumeItemResumeReqExtIEsExtContainer []ERABFailedToResumeItemResumeReqExtIEsExtField

// ERABFailedToResumeItemResumeResExtIEsExtContainer is ProtocolExtensionContainer {{E-RABFailedToResumeItemResumeRes-ExtIEs}} of TS 36.413: a list of ERABFailedToResumeItemResumeResExtIEsExtField values.
type ERABFailedToResumeItemResumeResExtIEsExtContainer []ERABFailedToResumeItemResumeResExtIEsExtField

// ERABDataForwardingItemExtIEsExtField is ProtocolExtensionField {{E-RABDataForwardingItem-ExtIEs}} of TS 36.413: an extension field.
type ERABDataForwardingItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABDataForwardingItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemExtIEsExtField) WithoutReplay() ERABDataForwardingItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABDataForwardingItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABDataForwardingItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABDataForwardingItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABDataForwardingItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABDataForwardingItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABDataForwardingItemExtIEsExtField{}
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
	var zero s04.ERABDataForwardingItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABDataForwardingItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABDataForwardingItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABDataForwardingItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABAdmittedItemExtIEsExtField is ProtocolExtensionField {{E-RABAdmittedItem-ExtIEs}} of TS 36.413: an extension field.
type ERABAdmittedItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABAdmittedItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemExtIEsExtField) WithoutReplay() ERABAdmittedItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABAdmittedItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABAdmittedItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABAdmittedItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABAdmittedItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABAdmittedItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABAdmittedItemExtIEsExtField{}
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
	var zero s04.ERABAdmittedItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABAdmittedItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABAdmittedItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABAdmittedItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABFailedToSetupItemHOReqAckExtIEsExtField is ProtocolExtensionField {{E-RABFailedToSetupItemHOReqAckExtIEs}} of TS 36.413: an extension field.
type ERABFailedToSetupItemHOReqAckExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABFailedToSetupItemHOReqAckExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToSetupItemHOReqAckExtIEsExtField) WithoutReplay() ERABFailedToSetupItemHOReqAckExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToSetupItemHOReqAckExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToSetupItemHOReqAckExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABFailedToSetupItemHOReqAckExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToSetupItemHOReqAckExtIEsExtField{}
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
	var zero s04.ERABFailedToSetupItemHOReqAckExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeSwitchedULItemExtIEsExtField is ProtocolExtensionField {{E-RABToBeSwitchedULItem-ExtIEs}} of TS 36.413: an extension field.
type ERABToBeSwitchedULItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABToBeSwitchedULItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemExtIEsExtField) WithoutReplay() ERABToBeSwitchedULItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSwitchedULItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSwitchedULItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABToBeSwitchedULItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedULItemExtIEsExtField{}
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
	var zero s04.ERABToBeSwitchedULItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeUpdatedItemExtIEsExtField is ProtocolExtensionField {{E-RABToBeUpdatedItem-ExtIEs}} of TS 36.413: an extension field.
type ERABToBeUpdatedItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABToBeUpdatedItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemExtIEsExtField) WithoutReplay() ERABToBeUpdatedItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeUpdatedItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeUpdatedItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABToBeUpdatedItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABToBeUpdatedItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABToBeUpdatedItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeUpdatedItemExtIEsExtField{}
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
	var zero s04.ERABToBeUpdatedItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABToBeUpdatedItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABToBeUpdatedItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABToBeUpdatedItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABSetupItemBearerSUResExtIEsExtField is ProtocolExtensionField {{E-RABSetupItemBearerSUResExtIEs}} of TS 36.413: an extension field.
type ERABSetupItemBearerSUResExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABSetupItemBearerSUResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResExtIEsExtField) WithoutReplay() ERABSetupItemBearerSUResExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupItemBearerSUResExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupItemBearerSUResExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABSetupItemBearerSUResExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemBearerSUResExtIEsExtField{}
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
	var zero s04.ERABSetupItemBearerSUResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABModifyItemBearerModResExtIEsExtField is ProtocolExtensionField {{E-RABModifyItemBearerModResExtIEs}} of TS 36.413: an extension field.
type ERABModifyItemBearerModResExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABModifyItemBearerModResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResExtIEsExtField) WithoutReplay() ERABModifyItemBearerModResExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyItemBearerModResExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyItemBearerModResExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABModifyItemBearerModResExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABModifyItemBearerModResExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABModifyItemBearerModResExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModResExtIEsExtField{}
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
	var zero s04.ERABModifyItemBearerModResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABModifyItemBearerModResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABModifyItemBearerModResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABModifyItemBearerModResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABReleaseItemBearerRelCompExtIEsExtField is ProtocolExtensionField {{E-RABReleaseItemBearerRelCompExtIEs}} of TS 36.413: an extension field.
type ERABReleaseItemBearerRelCompExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABReleaseItemBearerRelCompExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompExtIEsExtField) WithoutReplay() ERABReleaseItemBearerRelCompExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABReleaseItemBearerRelCompExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABReleaseItemBearerRelCompExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABReleaseItemBearerRelCompExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseItemBearerRelCompExtIEsExtField{}
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
	var zero s04.ERABReleaseItemBearerRelCompExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABSetupItemCtxtSUResExtIEsExtField is ProtocolExtensionField {{E-RABSetupItemCtxtSUResExtIEs}} of TS 36.413: an extension field.
type ERABSetupItemCtxtSUResExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABSetupItemCtxtSUResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResExtIEsExtField) WithoutReplay() ERABSetupItemCtxtSUResExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupItemCtxtSUResExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupItemCtxtSUResExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABSetupItemCtxtSUResExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemCtxtSUResExtIEsExtField{}
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
	var zero s04.ERABSetupItemCtxtSUResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeModifiedItemBearerModIndExtIEsExtField is ProtocolExtensionField {{E-RABToBeModifiedItemBearerModInd-ExtIEs}} of TS 36.413: an extension field.
type ERABToBeModifiedItemBearerModIndExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABToBeModifiedItemBearerModIndExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndExtIEsExtField) WithoutReplay() ERABToBeModifiedItemBearerModIndExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifiedItemBearerModIndExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifiedItemBearerModIndExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABToBeModifiedItemBearerModIndExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifiedItemBearerModIndExtIEsExtField{}
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
	var zero s04.ERABToBeModifiedItemBearerModIndExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABNotToBeModifiedItemBearerModIndExtIEsExtField is ProtocolExtensionField {{E-RABNotToBeModifiedItemBearerModInd-ExtIEs}} of TS 36.413: an extension field.
type ERABNotToBeModifiedItemBearerModIndExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndExtIEsExtField) WithoutReplay() ERABNotToBeModifiedItemBearerModIndExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABNotToBeModifiedItemBearerModIndExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABNotToBeModifiedItemBearerModIndExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABNotToBeModifiedItemBearerModIndExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABNotToBeModifiedItemBearerModIndExtIEsExtField{}
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
	var zero s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABModifyItemBearerModConfExtIEsExtField is ProtocolExtensionField {{E-RABModifyItemBearerModConfExtIEs}} of TS 36.413: an extension field.
type ERABModifyItemBearerModConfExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABModifyItemBearerModConfExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfExtIEsExtField) WithoutReplay() ERABModifyItemBearerModConfExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyItemBearerModConfExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyItemBearerModConfExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABModifyItemBearerModConfExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModConfExtIEsExtField{}
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
	var zero s04.ERABModifyItemBearerModConfExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABFailedToResumeItemResumeReqExtIEsExtField is ProtocolExtensionField {{E-RABFailedToResumeItemResumeReq-ExtIEs}} of TS 36.413: an extension field.
type ERABFailedToResumeItemResumeReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABFailedToResumeItemResumeReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqExtIEsExtField) WithoutReplay() ERABFailedToResumeItemResumeReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToResumeItemResumeReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeReqExtIEsExtField{}
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
	var zero s04.ERABFailedToResumeItemResumeReqExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABFailedToResumeItemResumeResExtIEsExtField is ProtocolExtensionField {{E-RABFailedToResumeItemResumeRes-ExtIEs}} of TS 36.413: an extension field.
type ERABFailedToResumeItemResumeResExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ERABFailedToResumeItemResumeResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeResExtIEsExtField) WithoutReplay() ERABFailedToResumeItemResumeResExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToResumeItemResumeResExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeResExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeResExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeResExtIEsExtField{}
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
	var zero s04.ERABFailedToResumeItemResumeResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABQoSParametersExtIEsPacketLossRateExtBinding binds PacketLossRate to the E-RABQoSParameters-ExtIEs object set of TS 36.413.
type ERABQoSParametersExtIEsPacketLossRateExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.PacketLossRateValueCodec
	inject func(s00.PacketLossRate,

	) ERABQoSParametersExtIEsValue

	get func(*ERABQoSParametersExtIEsValue,

	) (*s00.PacketLossRate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABQoSParametersExtIEsPacketLossRateExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABQoSParametersExtIEsPacketLossRateExtBinding) Codec() s01.PacketLossRateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABQoSParametersExtIEsPacketLossRateExtBinding) New(value s00.PacketLossRate,

) (ERABQoSParametersExtIEsExtField, error) {
	if b.inject == nil {
		return ERABQoSParametersExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABQoSParametersExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePacketLossRateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABQoSParametersExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABQoSParametersExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABQoSParametersExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABQoSParametersExtIEsPacketLossRateExtBinding) Get(field *ERABQoSParametersExtIEsExtField) (*s00.PacketLossRate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// EventTriggerExtIEField is ProtocolIE-Field {{EventTrigger-ExtIEs}} of TS 36.413: an information element field.
type EventTriggerExtIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.EventTriggerExtIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggerExtIEField) WithoutReplay() EventTriggerExtIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EventTriggerExtIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EventTriggerExtIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEventTriggerExtIEValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEventTriggerExtIEValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EventTriggerExtIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventTriggerExtIEField{}
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
	var zero s04.EventTriggerExtIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEventTriggerExtIEValueMethodReason(zero, v.Id), s04.BridgeEventTriggerExtIEValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeEventTriggerExtIEValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCTransferTypeReplyExtIEsIEField uses the ProtocolIE-Field shape for object set EN-DCTransferTypeReply-ExtIEs of TS 36.413.
type ENDCTransferTypeReplyExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ENDCTransferTypeReplyExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeReplyExtIEsIEField) WithoutReplay() ENDCTransferTypeReplyExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCTransferTypeReplyExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCTransferTypeReplyExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeENDCTransferTypeReplyExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCTransferTypeReplyExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCTransferTypeReplyExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCTransferTypeReplyExtIEsIEField{}
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
	var zero s04.ENDCTransferTypeReplyExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCTransferTypeReplyExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCTransferTypeReplyExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeENDCTransferTypeReplyExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCTransferTypeReplyExtIEsIEContainer uses the ProtocolIE-Container shape for object set EN-DCTransferTypeReply-ExtIEs of TS 36.413: a list of ENDCTransferTypeReplyExtIEsIEField values.
type ENDCTransferTypeReplyExtIEsIEContainer []ENDCTransferTypeReplyExtIEsIEField

// ENDCTransferTypeRequestExtIEsIEField uses the ProtocolIE-Field shape for object set EN-DCTransferTypeRequest-ExtIEs of TS 36.413.
type ENDCTransferTypeRequestExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ENDCTransferTypeRequestExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeRequestExtIEsIEField) WithoutReplay() ENDCTransferTypeRequestExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCTransferTypeRequestExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCTransferTypeRequestExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeENDCTransferTypeRequestExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCTransferTypeRequestExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCTransferTypeRequestExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCTransferTypeRequestExtIEsIEField{}
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
	var zero s04.ENDCTransferTypeRequestExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCTransferTypeRequestExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCTransferTypeRequestExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeENDCTransferTypeRequestExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCTransferTypeRequestExtIEsIEContainer uses the ProtocolIE-Container shape for object set EN-DCTransferTypeRequest-ExtIEs of TS 36.413: a list of ENDCTransferTypeRequestExtIEsIEField values.
type ENDCTransferTypeRequestExtIEsIEContainer []ENDCTransferTypeRequestExtIEsIEField

// ERABAdmittedItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABAdmittedItem-ExtIEs of TS 36.413.
type ERABAdmittedItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABAdmittedItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemExtIEsIEField) WithoutReplay() ERABAdmittedItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABAdmittedItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABAdmittedItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABAdmittedItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABAdmittedItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABAdmittedItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABAdmittedItemExtIEsIEField{}
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
	var zero s04.ERABAdmittedItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABAdmittedItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABAdmittedItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABAdmittedItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABAdmittedItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABAdmittedItem-ExtIEs of TS 36.413: a list of ERABAdmittedItemExtIEsIEField values.
type ERABAdmittedItemExtIEsIEContainer []ERABAdmittedItemExtIEsIEField

// ERABDataForwardingItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABDataForwardingItem-ExtIEs of TS 36.413.
type ERABDataForwardingItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABDataForwardingItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemExtIEsIEField) WithoutReplay() ERABDataForwardingItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABDataForwardingItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABDataForwardingItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABDataForwardingItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABDataForwardingItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABDataForwardingItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABDataForwardingItemExtIEsIEField{}
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
	var zero s04.ERABDataForwardingItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABDataForwardingItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABDataForwardingItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABDataForwardingItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABDataForwardingItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABDataForwardingItem-ExtIEs of TS 36.413: a list of ERABDataForwardingItemExtIEsIEField values.
type ERABDataForwardingItemExtIEsIEContainer []ERABDataForwardingItemExtIEsIEField

// ERABFailedToResumeItemResumeReqExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABFailedToResumeItemResumeReq-ExtIEs of TS 36.413.
type ERABFailedToResumeItemResumeReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABFailedToResumeItemResumeReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqExtIEsIEField) WithoutReplay() ERABFailedToResumeItemResumeReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToResumeItemResumeReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeReqExtIEsIEField{}
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
	var zero s04.ERABFailedToResumeItemResumeReqExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABFailedToResumeItemResumeReqExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABFailedToResumeItemResumeReq-ExtIEs of TS 36.413: a list of ERABFailedToResumeItemResumeReqExtIEsIEField values.
type ERABFailedToResumeItemResumeReqExtIEsIEContainer []ERABFailedToResumeItemResumeReqExtIEsIEField

// ERABFailedToResumeItemResumeResExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABFailedToResumeItemResumeRes-ExtIEs of TS 36.413.
type ERABFailedToResumeItemResumeResExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABFailedToResumeItemResumeResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeResExtIEsIEField) WithoutReplay() ERABFailedToResumeItemResumeResExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToResumeItemResumeResExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeResExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeResExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeResExtIEsIEField{}
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
	var zero s04.ERABFailedToResumeItemResumeResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABFailedToResumeItemResumeResExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABFailedToResumeItemResumeRes-ExtIEs of TS 36.413: a list of ERABFailedToResumeItemResumeResExtIEsIEField values.
type ERABFailedToResumeItemResumeResExtIEsIEContainer []ERABFailedToResumeItemResumeResExtIEsIEField

// ERABFailedToSetupItemHOReqAckExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABFailedToSetupItemHOReqAckExtIEs of TS 36.413.
type ERABFailedToSetupItemHOReqAckExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABFailedToSetupItemHOReqAckExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToSetupItemHOReqAckExtIEsIEField) WithoutReplay() ERABFailedToSetupItemHOReqAckExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToSetupItemHOReqAckExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToSetupItemHOReqAckExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABFailedToSetupItemHOReqAckExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToSetupItemHOReqAckExtIEsIEField{}
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
	var zero s04.ERABFailedToSetupItemHOReqAckExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABFailedToSetupItemHOReqAckExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABFailedToSetupItemHOReqAckExtIEs of TS 36.413: a list of ERABFailedToSetupItemHOReqAckExtIEsIEField values.
type ERABFailedToSetupItemHOReqAckExtIEsIEContainer []ERABFailedToSetupItemHOReqAckExtIEsIEField

// ERABItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABItem-ExtIEs of TS 36.413.
type ERABItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemExtIEsIEField) WithoutReplay() ERABItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABItemExtIEsIEField{}
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
	var zero s04.ERABItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABItem-ExtIEs of TS 36.413: a list of ERABItemExtIEsIEField values.
type ERABItemExtIEsIEContainer []ERABItemExtIEsIEField

// ERABQoSParametersExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABQoSParameters-ExtIEs of TS 36.413.
type ERABQoSParametersExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABQoSParametersExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABQoSParametersExtIEsIEField) WithoutReplay() ERABQoSParametersExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABQoSParametersExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABQoSParametersExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABQoSParametersExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABQoSParametersExtIEsIEField{}
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
	var zero ERABQoSParametersExtIEsValue

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

// ERABQoSParametersExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABQoSParameters-ExtIEs of TS 36.413: a list of ERABQoSParametersExtIEsIEField values.
type ERABQoSParametersExtIEsIEContainer []ERABQoSParametersExtIEsIEField

// ERABModifyItemBearerModConfExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABModifyItemBearerModConfExtIEs of TS 36.413.
type ERABModifyItemBearerModConfExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABModifyItemBearerModConfExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfExtIEsIEField) WithoutReplay() ERABModifyItemBearerModConfExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyItemBearerModConfExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyItemBearerModConfExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABModifyItemBearerModConfExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModConfExtIEsIEField{}
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
	var zero s04.ERABModifyItemBearerModConfExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABModifyItemBearerModConfExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABModifyItemBearerModConfExtIEs of TS 36.413: a list of ERABModifyItemBearerModConfExtIEsIEField values.
type ERABModifyItemBearerModConfExtIEsIEContainer []ERABModifyItemBearerModConfExtIEsIEField

// ERABModifyItemBearerModResExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABModifyItemBearerModResExtIEs of TS 36.413.
type ERABModifyItemBearerModResExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABModifyItemBearerModResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResExtIEsIEField) WithoutReplay() ERABModifyItemBearerModResExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyItemBearerModResExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyItemBearerModResExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABModifyItemBearerModResExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABModifyItemBearerModResExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABModifyItemBearerModResExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModResExtIEsIEField{}
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
	var zero s04.ERABModifyItemBearerModResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABModifyItemBearerModResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABModifyItemBearerModResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABModifyItemBearerModResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABModifyItemBearerModResExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABModifyItemBearerModResExtIEs of TS 36.413: a list of ERABModifyItemBearerModResExtIEsIEField values.
type ERABModifyItemBearerModResExtIEsIEContainer []ERABModifyItemBearerModResExtIEsIEField

// ERABNotToBeModifiedItemBearerModIndExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABNotToBeModifiedItemBearerModInd-ExtIEs of TS 36.413.
type ERABNotToBeModifiedItemBearerModIndExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndExtIEsIEField) WithoutReplay() ERABNotToBeModifiedItemBearerModIndExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABNotToBeModifiedItemBearerModIndExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABNotToBeModifiedItemBearerModIndExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABNotToBeModifiedItemBearerModIndExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABNotToBeModifiedItemBearerModIndExtIEsIEField{}
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
	var zero s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABNotToBeModifiedItemBearerModIndExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABNotToBeModifiedItemBearerModInd-ExtIEs of TS 36.413: a list of ERABNotToBeModifiedItemBearerModIndExtIEsIEField values.
type ERABNotToBeModifiedItemBearerModIndExtIEsIEContainer []ERABNotToBeModifiedItemBearerModIndExtIEsIEField

// ERABReleaseItemBearerRelCompExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABReleaseItemBearerRelCompExtIEs of TS 36.413.
type ERABReleaseItemBearerRelCompExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABReleaseItemBearerRelCompExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompExtIEsIEField) WithoutReplay() ERABReleaseItemBearerRelCompExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABReleaseItemBearerRelCompExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABReleaseItemBearerRelCompExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABReleaseItemBearerRelCompExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseItemBearerRelCompExtIEsIEField{}
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
	var zero s04.ERABReleaseItemBearerRelCompExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABReleaseItemBearerRelCompExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABReleaseItemBearerRelCompExtIEs of TS 36.413: a list of ERABReleaseItemBearerRelCompExtIEsIEField values.
type ERABReleaseItemBearerRelCompExtIEsIEContainer []ERABReleaseItemBearerRelCompExtIEsIEField

// ERABSecurityResultItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABSecurityResultItem-ExtIEs of TS 36.413.
type ERABSecurityResultItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABSecurityResultItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultItemExtIEsIEField) WithoutReplay() ERABSecurityResultItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSecurityResultItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSecurityResultItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABSecurityResultItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABSecurityResultItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABSecurityResultItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSecurityResultItemExtIEsIEField{}
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
	var zero s04.ERABSecurityResultItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABSecurityResultItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABSecurityResultItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABSecurityResultItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABSecurityResultItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABSecurityResultItem-ExtIEs of TS 36.413: a list of ERABSecurityResultItemExtIEsIEField values.
type ERABSecurityResultItemExtIEsIEContainer []ERABSecurityResultItemExtIEsIEField

// ERABSetupItemBearerSUResExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABSetupItemBearerSUResExtIEs of TS 36.413.
type ERABSetupItemBearerSUResExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABSetupItemBearerSUResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResExtIEsIEField) WithoutReplay() ERABSetupItemBearerSUResExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupItemBearerSUResExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupItemBearerSUResExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABSetupItemBearerSUResExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemBearerSUResExtIEsIEField{}
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
	var zero s04.ERABSetupItemBearerSUResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABSetupItemBearerSUResExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABSetupItemBearerSUResExtIEs of TS 36.413: a list of ERABSetupItemBearerSUResExtIEsIEField values.
type ERABSetupItemBearerSUResExtIEsIEContainer []ERABSetupItemBearerSUResExtIEsIEField

// ERABSetupItemCtxtSUResExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABSetupItemCtxtSUResExtIEs of TS 36.413.
type ERABSetupItemCtxtSUResExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABSetupItemCtxtSUResExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResExtIEsIEField) WithoutReplay() ERABSetupItemCtxtSUResExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupItemCtxtSUResExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupItemCtxtSUResExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABSetupItemCtxtSUResExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemCtxtSUResExtIEsIEField{}
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
	var zero s04.ERABSetupItemCtxtSUResExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABSetupItemCtxtSUResExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABSetupItemCtxtSUResExtIEs of TS 36.413: a list of ERABSetupItemCtxtSUResExtIEsIEField values.
type ERABSetupItemCtxtSUResExtIEsIEContainer []ERABSetupItemCtxtSUResExtIEsIEField

// ERABToBeModifiedItemBearerModIndExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeModifiedItemBearerModInd-ExtIEs of TS 36.413.
type ERABToBeModifiedItemBearerModIndExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABToBeModifiedItemBearerModIndExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndExtIEsIEField) WithoutReplay() ERABToBeModifiedItemBearerModIndExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifiedItemBearerModIndExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifiedItemBearerModIndExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABToBeModifiedItemBearerModIndExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifiedItemBearerModIndExtIEsIEField{}
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
	var zero s04.ERABToBeModifiedItemBearerModIndExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeModifiedItemBearerModIndExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeModifiedItemBearerModInd-ExtIEs of TS 36.413: a list of ERABToBeModifiedItemBearerModIndExtIEsIEField values.
type ERABToBeModifiedItemBearerModIndExtIEsIEContainer []ERABToBeModifiedItemBearerModIndExtIEsIEField

// ERABToBeSwitchedULItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeSwitchedULItem-ExtIEs of TS 36.413.
type ERABToBeSwitchedULItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABToBeSwitchedULItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemExtIEsIEField) WithoutReplay() ERABToBeSwitchedULItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSwitchedULItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSwitchedULItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABToBeSwitchedULItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedULItemExtIEsIEField{}
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
	var zero s04.ERABToBeSwitchedULItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeSwitchedULItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeSwitchedULItem-ExtIEs of TS 36.413: a list of ERABToBeSwitchedULItemExtIEsIEField values.
type ERABToBeSwitchedULItemExtIEsIEContainer []ERABToBeSwitchedULItemExtIEsIEField

// ERABToBeUpdatedItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeUpdatedItem-ExtIEs of TS 36.413.
type ERABToBeUpdatedItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABToBeUpdatedItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemExtIEsIEField) WithoutReplay() ERABToBeUpdatedItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeUpdatedItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeUpdatedItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABToBeUpdatedItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABToBeUpdatedItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABToBeUpdatedItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeUpdatedItemExtIEsIEField{}
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
	var zero s04.ERABToBeUpdatedItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABToBeUpdatedItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABToBeUpdatedItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABToBeUpdatedItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeUpdatedItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeUpdatedItem-ExtIEs of TS 36.413: a list of ERABToBeUpdatedItemExtIEsIEField values.
type ERABToBeUpdatedItemExtIEsIEContainer []ERABToBeUpdatedItemExtIEsIEField

// ERABUsageReportItemExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABUsageReportItem-ExtIEs of TS 36.413.
type ERABUsageReportItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ERABUsageReportItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemExtIEsIEField) WithoutReplay() ERABUsageReportItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABUsageReportItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABUsageReportItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeERABUsageReportItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeERABUsageReportItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ERABUsageReportItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABUsageReportItemExtIEsIEField{}
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
	var zero s04.ERABUsageReportItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeERABUsageReportItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeERABUsageReportItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeERABUsageReportItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABUsageReportItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABUsageReportItem-ExtIEs of TS 36.413: a list of ERABUsageReportItemExtIEsIEField values.
type ERABUsageReportItemExtIEsIEContainer []ERABUsageReportItemExtIEsIEField

// EUTRANCGIExtIEsIEField uses the ProtocolIE-Field shape for object set EUTRAN-CGI-ExtIEs of TS 36.413.
type EUTRANCGIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.EUTRANCGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EUTRANCGIExtIEsIEField) WithoutReplay() EUTRANCGIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EUTRANCGIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EUTRANCGIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEUTRANCGIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEUTRANCGIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EUTRANCGIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EUTRANCGIExtIEsIEField{}
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
	var zero s04.EUTRANCGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEUTRANCGIExtIEsValueMethodReason(zero, v.Id), s04.BridgeEUTRANCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeEUTRANCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// EUTRANCGIExtIEsIEContainer uses the ProtocolIE-Container shape for object set EUTRAN-CGI-ExtIEs of TS 36.413: a list of EUTRANCGIExtIEsIEField values.
type EUTRANCGIExtIEsIEContainer []EUTRANCGIExtIEsIEField

// EmergencyAreaIDBroadcastItemExtIEsIEField uses the ProtocolIE-Field shape for object set EmergencyAreaID-Broadcast-Item-ExtIEs of TS 36.413.
type EmergencyAreaIDBroadcastItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.EmergencyAreaIDBroadcastItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDBroadcastItemExtIEsIEField) WithoutReplay() EmergencyAreaIDBroadcastItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EmergencyAreaIDBroadcastItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EmergencyAreaIDBroadcastItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EmergencyAreaIDBroadcastItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDBroadcastItemExtIEsIEField{}
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
	var zero s04.EmergencyAreaIDBroadcastItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// EmergencyAreaIDBroadcastItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set EmergencyAreaID-Broadcast-Item-ExtIEs of TS 36.413: a list of EmergencyAreaIDBroadcastItemExtIEsIEField values.
type EmergencyAreaIDBroadcastItemExtIEsIEContainer []EmergencyAreaIDBroadcastItemExtIEsIEField

// EmergencyAreaIDCancelledItemExtIEsIEField uses the ProtocolIE-Field shape for object set EmergencyAreaID-Cancelled-Item-ExtIEs of TS 36.413.
type EmergencyAreaIDCancelledItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.EmergencyAreaIDCancelledItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledItemExtIEsIEField) WithoutReplay() EmergencyAreaIDCancelledItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EmergencyAreaIDCancelledItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EmergencyAreaIDCancelledItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EmergencyAreaIDCancelledItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDCancelledItemExtIEsIEField{}
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
	var zero s04.EmergencyAreaIDCancelledItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// EmergencyAreaIDCancelledItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set EmergencyAreaID-Cancelled-Item-ExtIEs of TS 36.413: a list of EmergencyAreaIDCancelledItemExtIEsIEField values.
type EmergencyAreaIDCancelledItemExtIEsIEContainer []EmergencyAreaIDCancelledItemExtIEsIEField

// EventL1LoggedMDTConfigExtIEsIEField uses the ProtocolIE-Field shape for object set EventL1LoggedMDTConfig-ExtIEs of TS 36.413.
type EventL1LoggedMDTConfigExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.EventL1LoggedMDTConfigExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventL1LoggedMDTConfigExtIEsIEField) WithoutReplay() EventL1LoggedMDTConfigExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *EventL1LoggedMDTConfigExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *EventL1LoggedMDTConfigExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *EventL1LoggedMDTConfigExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventL1LoggedMDTConfigExtIEsIEField{}
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
	var zero s04.EventL1LoggedMDTConfigExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodReason(zero, v.Id), s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// EventL1LoggedMDTConfigExtIEsIEContainer uses the ProtocolIE-Container shape for object set EventL1LoggedMDTConfig-ExtIEs of TS 36.413: a list of EventL1LoggedMDTConfigExtIEsIEField values.
type EventL1LoggedMDTConfigExtIEsIEContainer []EventL1LoggedMDTConfigExtIEsIEField

// ExpectedUEActivityBehaviourExtIEsIEField uses the ProtocolIE-Field shape for object set ExpectedUEActivityBehaviour-ExtIEs of TS 36.413.
type ExpectedUEActivityBehaviourExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.ExpectedUEActivityBehaviourExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEActivityBehaviourExtIEsIEField) WithoutReplay() ExpectedUEActivityBehaviourExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ExpectedUEActivityBehaviourExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ExpectedUEActivityBehaviourExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ExpectedUEActivityBehaviourExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ExpectedUEActivityBehaviourExtIEsIEField{}
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
	var zero s05.ExpectedUEActivityBehaviourExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodReason(zero, v.Id), s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ExpectedUEActivityBehaviourExtIEsIEContainer uses the ProtocolIE-Container shape for object set ExpectedUEActivityBehaviour-ExtIEs of TS 36.413: a list of ExpectedUEActivityBehaviourExtIEsIEField values.
type ExpectedUEActivityBehaviourExtIEsIEContainer []ExpectedUEActivityBehaviourExtIEsIEField

// ExpectedUEBehaviourExtIEsIEField uses the ProtocolIE-Field shape for object set ExpectedUEBehaviour-ExtIEs of TS 36.413.
type ExpectedUEBehaviourExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.ExpectedUEBehaviourExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEBehaviourExtIEsIEField) WithoutReplay() ExpectedUEBehaviourExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ExpectedUEBehaviourExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ExpectedUEBehaviourExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeExpectedUEBehaviourExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeExpectedUEBehaviourExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ExpectedUEBehaviourExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ExpectedUEBehaviourExtIEsIEField{}
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
	var zero s05.ExpectedUEBehaviourExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeExpectedUEBehaviourExtIEsValueMethodReason(zero, v.Id), s05.BridgeExpectedUEBehaviourExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeExpectedUEBehaviourExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ExpectedUEBehaviourExtIEsIEContainer uses the ProtocolIE-Container shape for object set ExpectedUEBehaviour-ExtIEs of TS 36.413: a list of ExpectedUEBehaviourExtIEsIEField values.
type ExpectedUEBehaviourExtIEsIEContainer []ExpectedUEBehaviourExtIEsIEField

// FiveGSTAIExtIEsIEField uses the ProtocolIE-Field shape for object set FiveGSTAI-ExtIEs of TS 36.413.
type FiveGSTAIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.FiveGSTAIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FiveGSTAIExtIEsIEField) WithoutReplay() FiveGSTAIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *FiveGSTAIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *FiveGSTAIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeFiveGSTAIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeFiveGSTAIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *FiveGSTAIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = FiveGSTAIExtIEsIEField{}
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
	var zero s05.FiveGSTAIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeFiveGSTAIExtIEsValueMethodReason(zero, v.Id), s05.BridgeFiveGSTAIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeFiveGSTAIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// FiveGSTAIExtIEsIEContainer uses the ProtocolIE-Container shape for object set FiveGSTAI-ExtIEs of TS 36.413: a list of FiveGSTAIExtIEsIEField values.
type FiveGSTAIExtIEsIEContainer []FiveGSTAIExtIEsIEField

// ForbiddenLAsItemExtIEsIEField uses the ProtocolIE-Field shape for object set ForbiddenLAs-Item-ExtIEs of TS 36.413.
type ForbiddenLAsItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.ForbiddenLAsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenLAsItemExtIEsIEField) WithoutReplay() ForbiddenLAsItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ForbiddenLAsItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ForbiddenLAsItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeForbiddenLAsItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeForbiddenLAsItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ForbiddenLAsItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ForbiddenLAsItemExtIEsIEField{}
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
	var zero s05.ForbiddenLAsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeForbiddenLAsItemExtIEsValueMethodReason(zero, v.Id), s05.BridgeForbiddenLAsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeForbiddenLAsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ForbiddenLAsItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set ForbiddenLAs-Item-ExtIEs of TS 36.413: a list of ForbiddenLAsItemExtIEsIEField values.
type ForbiddenLAsItemExtIEsIEContainer []ForbiddenLAsItemExtIEsIEField

// ForbiddenTAsItemExtIEsIEField uses the ProtocolIE-Field shape for object set ForbiddenTAs-Item-ExtIEs of TS 36.413.
type ForbiddenTAsItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.ForbiddenTAsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenTAsItemExtIEsIEField) WithoutReplay() ForbiddenTAsItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ForbiddenTAsItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ForbiddenTAsItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeForbiddenTAsItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeForbiddenTAsItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ForbiddenTAsItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ForbiddenTAsItemExtIEsIEField{}
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
	var zero s05.ForbiddenTAsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeForbiddenTAsItemExtIEsValueMethodReason(zero, v.Id), s05.BridgeForbiddenTAsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeForbiddenTAsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ForbiddenTAsItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set ForbiddenTAs-Item-ExtIEs of TS 36.413: a list of ForbiddenTAsItemExtIEsIEField values.
type ForbiddenTAsItemExtIEsIEContainer []ForbiddenTAsItemExtIEsIEField

// EventTriggerExtIEValueERABIEContainerListValueCodec is the concrete ValueCodec[EventTriggerExtIEValueERABIEContainerList].
type EventTriggerExtIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTriggerExtIEValueERABIEContainerList, error)
	encode  func(EventTriggerExtIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTriggerExtIEValueERABIEContainerList, aper.DecodeState) (EventTriggerExtIEValueERABIEContainerList, aper.Snapshot)
	compare func(EventTriggerExtIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggerExtIEValueERABIEContainerListValueCodec) New(value EventTriggerExtIEValueERABIEContainerList) (EventTriggerExtIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return EventTriggerExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggerExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggerExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggerExtIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggerExtIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggerExtIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggerExtIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggerExtIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggerExtIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggerExtIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggerExtIEValueERABIEContainerListValueCodec) EncodeAPER(value EventTriggerExtIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventTriggerExtIEValueERABIEContainerListValueCodec) encodeBudgetValue(value EventTriggerExtIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggerExtIEValueERABIEContainerListValueCodec) encodeChanged(value EventTriggerExtIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggerExtIEValueERABIEContainerList is E-RAB-IE-ContainerList {{EventTrigger-ExtIEs}} of TS 36.413: a list of information element fields.
type EventTriggerExtIEValueERABIEContainerList []EventTriggerExtIEValueProtocolIESingleContainer

// EventTriggerExtIEContainer is ProtocolIE-Container {{EventTrigger-ExtIEs}} of TS 36.413: a list of EventTriggerExtIEField values.
type EventTriggerExtIEContainer []EventTriggerExtIEField

// ENDCTransferTypeRequestExtIEsExtFieldValueCodec is the concrete ValueCodec[ENDCTransferTypeRequestExtIEsExtField].
type ENDCTransferTypeRequestExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtField, error)
	encode  func(ENDCTransferTypeRequestExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCTransferTypeRequestExtIEsExtField, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtField, aper.Snapshot)
	compare func(ENDCTransferTypeRequestExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCTransferTypeRequestExtIEsExtFieldValueCodec) New(value ENDCTransferTypeRequestExtIEsExtField) (ENDCTransferTypeRequestExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCTransferTypeRequestExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCTransferTypeRequestExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCTransferTypeRequestExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCTransferTypeRequestExtIEsExtFieldValueCodec) EncodeAPER(value ENDCTransferTypeRequestExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCTransferTypeRequestExtIEsExtFieldValueCodec) encodeBudgetValue(value ENDCTransferTypeRequestExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCTransferTypeRequestExtIEsExtFieldValueCodec) encodeChanged(value ENDCTransferTypeRequestExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABAdmittedItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABAdmittedItemExtIEsExtField].
type ERABAdmittedItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItemExtIEsExtField, error)
	encode  func(ERABAdmittedItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItemExtIEsExtField, aper.DecodeState) (ERABAdmittedItemExtIEsExtField, aper.Snapshot)
	compare func(ERABAdmittedItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemExtIEsExtFieldValueCodec) New(value ERABAdmittedItemExtIEsExtField) (ERABAdmittedItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABAdmittedItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABAdmittedItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemExtIEsExtFieldValueCodec) encodeChanged(value ERABAdmittedItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABDataForwardingItemExtIEsExtField].
type ERABDataForwardingItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItemExtIEsExtField, error)
	encode  func(ERABDataForwardingItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItemExtIEsExtField, aper.DecodeState) (ERABDataForwardingItemExtIEsExtField, aper.Snapshot)
	compare func(ERABDataForwardingItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemExtIEsExtFieldValueCodec) New(value ERABDataForwardingItemExtIEsExtField) (ERABDataForwardingItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABDataForwardingItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABDataForwardingItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemExtIEsExtFieldValueCodec) encodeChanged(value ERABDataForwardingItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReqExtIEsExtField].
type ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtField, error)
	encode  func(ERABFailedToResumeItemResumeReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReqExtIEsExtField, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtField, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) New(value ERABFailedToResumeItemResumeReqExtIEsExtField) (ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeResExtIEsExtField].
type ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtField, error)
	encode  func(ERABFailedToResumeItemResumeResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeResExtIEsExtField, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtField, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) New(value ERABFailedToResumeItemResumeResExtIEsExtField) (ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeResExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) encodeChanged(value ERABFailedToResumeItemResumeResExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABFailedToSetupItemHOReqAckExtIEsExtField].
type ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtField, error)
	encode  func(ERABFailedToSetupItemHOReqAckExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.Snapshot)
	compare func(ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) New(value ERABFailedToSetupItemHOReqAckExtIEsExtField) (ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) EncodeAPER(value ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABFailedToSetupItemHOReqAckExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) encodeChanged(value ERABFailedToSetupItemHOReqAckExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABItemExtIEsExtField].
type ERABItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItemExtIEsExtField, error)
	encode  func(ERABItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItemExtIEsExtField, aper.DecodeState) (ERABItemExtIEsExtField, aper.Snapshot)
	compare func(ERABItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemExtIEsExtFieldValueCodec) New(value ERABItemExtIEsExtField) (ERABItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemExtIEsExtFieldValueCodec) encodeChanged(value ERABItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABModifyItemBearerModConfExtIEsExtField].
type ERABModifyItemBearerModConfExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtField, error)
	encode  func(ERABModifyItemBearerModConfExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConfExtIEsExtField, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtField, aper.Snapshot)
	compare func(ERABModifyItemBearerModConfExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) New(value ERABModifyItemBearerModConfExtIEsExtField) (ERABModifyItemBearerModConfExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) EncodeAPER(value ERABModifyItemBearerModConfExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConfExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) encodeChanged(value ERABModifyItemBearerModConfExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABModifyItemBearerModResExtIEsExtField].
type ERABModifyItemBearerModResExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtField, error)
	encode  func(ERABModifyItemBearerModResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModResExtIEsExtField, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtField, aper.Snapshot)
	compare func(ERABModifyItemBearerModResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResExtIEsExtFieldValueCodec) New(value ERABModifyItemBearerModResExtIEsExtField) (ERABModifyItemBearerModResExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResExtIEsExtFieldValueCodec) EncodeAPER(value ERABModifyItemBearerModResExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABModifyItemBearerModResExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResExtIEsExtFieldValueCodec) encodeChanged(value ERABModifyItemBearerModResExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABNotToBeModifiedItemBearerModIndExtIEsExtField].
type ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtField, error)
	encode  func(ERABNotToBeModifiedItemBearerModIndExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot)
	compare func(ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) New(value ERABNotToBeModifiedItemBearerModIndExtIEsExtField) (ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABQoSParametersExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABQoSParametersExtIEsExtField].
type ERABQoSParametersExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABQoSParametersExtIEsExtField, error)
	encode  func(ERABQoSParametersExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABQoSParametersExtIEsExtField, aper.DecodeState) (ERABQoSParametersExtIEsExtField, aper.Snapshot)
	compare func(ERABQoSParametersExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABQoSParametersExtIEsExtFieldValueCodec) New(value ERABQoSParametersExtIEsExtField) (ERABQoSParametersExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABQoSParametersExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABQoSParametersExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABQoSParametersExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABQoSParametersExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABQoSParametersExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABQoSParametersExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABQoSParametersExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABQoSParametersExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABQoSParametersExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABQoSParametersExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABQoSParametersExtIEsExtFieldValueCodec) EncodeAPER(value ERABQoSParametersExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABQoSParametersExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABQoSParametersExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABQoSParametersExtIEsExtFieldValueCodec) encodeChanged(value ERABQoSParametersExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABReleaseItemBearerRelCompExtIEsExtField].
type ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtField, error)
	encode  func(ERABReleaseItemBearerRelCompExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelCompExtIEsExtField, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtField, aper.Snapshot)
	compare func(ERABReleaseItemBearerRelCompExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) New(value ERABReleaseItemBearerRelCompExtIEsExtField) (ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelCompExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) encodeChanged(value ERABReleaseItemBearerRelCompExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSecurityResultItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABSecurityResultItemExtIEsExtField].
type ERABSecurityResultItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultItemExtIEsExtField, error)
	encode  func(ERABSecurityResultItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultItemExtIEsExtField, aper.DecodeState) (ERABSecurityResultItemExtIEsExtField, aper.Snapshot)
	compare func(ERABSecurityResultItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultItemExtIEsExtFieldValueCodec) New(value ERABSecurityResultItemExtIEsExtField) (ERABSecurityResultItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABSecurityResultItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABSecurityResultItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultItemExtIEsExtFieldValueCodec) encodeChanged(value ERABSecurityResultItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABSetupItemBearerSUResExtIEsExtField].
type ERABSetupItemBearerSUResExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtField, error)
	encode  func(ERABSetupItemBearerSUResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSUResExtIEsExtField, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtField, aper.Snapshot)
	compare func(ERABSetupItemBearerSUResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) New(value ERABSetupItemBearerSUResExtIEsExtField) (ERABSetupItemBearerSUResExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) EncodeAPER(value ERABSetupItemBearerSUResExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABSetupItemBearerSUResExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) encodeChanged(value ERABSetupItemBearerSUResExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABSetupItemCtxtSUResExtIEsExtField].
type ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtField, error)
	encode  func(ERABSetupItemCtxtSUResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSUResExtIEsExtField, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtField, aper.Snapshot)
	compare func(ERABSetupItemCtxtSUResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) New(value ERABSetupItemCtxtSUResExtIEsExtField) (ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSUResExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) encodeChanged(value ERABSetupItemCtxtSUResExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModIndExtIEsExtField].
type ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtField, error)
	encode  func(ERABToBeModifiedItemBearerModIndExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) New(value ERABToBeModifiedItemBearerModIndExtIEsExtField) (ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItemExtIEsExtField].
type ERABToBeSwitchedULItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtField, error)
	encode  func(ERABToBeSwitchedULItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItemExtIEsExtField, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeSwitchedULItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) New(value ERABToBeSwitchedULItemExtIEsExtField) (ERABToBeSwitchedULItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeSwitchedULItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeSwitchedULItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeUpdatedItemExtIEsExtField].
type ERABToBeUpdatedItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtField, error)
	encode  func(ERABToBeUpdatedItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItemExtIEsExtField, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeUpdatedItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemExtIEsExtFieldValueCodec) New(value ERABToBeUpdatedItemExtIEsExtField) (ERABToBeUpdatedItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeUpdatedItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeUpdatedItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeUpdatedItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABUsageReportItemExtIEsExtField].
type ERABUsageReportItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItemExtIEsExtField, error)
	encode  func(ERABUsageReportItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItemExtIEsExtField, aper.DecodeState) (ERABUsageReportItemExtIEsExtField, aper.Snapshot)
	compare func(ERABUsageReportItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemExtIEsExtFieldValueCodec) New(value ERABUsageReportItemExtIEsExtField) (ERABUsageReportItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABUsageReportItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABUsageReportItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemExtIEsExtFieldValueCodec) encodeChanged(value ERABUsageReportItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EUTRANCGIExtIEsExtFieldValueCodec is the concrete ValueCodec[EUTRANCGIExtIEsExtField].
type EUTRANCGIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EUTRANCGIExtIEsExtField, error)
	encode  func(EUTRANCGIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EUTRANCGIExtIEsExtField, aper.DecodeState) (EUTRANCGIExtIEsExtField, aper.Snapshot)
	compare func(EUTRANCGIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EUTRANCGIExtIEsExtFieldValueCodec) New(value EUTRANCGIExtIEsExtField) (EUTRANCGIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return EUTRANCGIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EUTRANCGIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANCGIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EUTRANCGIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EUTRANCGIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EUTRANCGIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EUTRANCGIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EUTRANCGIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EUTRANCGIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EUTRANCGIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EUTRANCGIExtIEsExtFieldValueCodec) EncodeAPER(value EUTRANCGIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EUTRANCGIExtIEsExtFieldValueCodec) encodeBudgetValue(value EUTRANCGIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EUTRANCGIExtIEsExtFieldValueCodec) encodeChanged(value EUTRANCGIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec is the concrete ValueCodec[EmergencyAreaIDBroadcastItemExtIEsExtField].
type EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtField, error)
	encode  func(EmergencyAreaIDBroadcastItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDBroadcastItemExtIEsExtField, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtField, aper.Snapshot)
	compare func(EmergencyAreaIDBroadcastItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) New(value EmergencyAreaIDBroadcastItemExtIEsExtField) (EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) EncodeAPER(value EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) encodeBudgetValue(value EmergencyAreaIDBroadcastItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) encodeChanged(value EmergencyAreaIDBroadcastItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec is the concrete ValueCodec[EmergencyAreaIDCancelledItemExtIEsExtField].
type EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtField, error)
	encode  func(EmergencyAreaIDCancelledItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDCancelledItemExtIEsExtField, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtField, aper.Snapshot)
	compare func(EmergencyAreaIDCancelledItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) New(value EmergencyAreaIDCancelledItemExtIEsExtField) (EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) EncodeAPER(value EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) encodeBudgetValue(value EmergencyAreaIDCancelledItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) encodeChanged(value EmergencyAreaIDCancelledItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventL1LoggedMDTConfigExtIEsExtFieldValueCodec is the concrete ValueCodec[EventL1LoggedMDTConfigExtIEsExtField].
type EventL1LoggedMDTConfigExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtField, error)
	encode  func(EventL1LoggedMDTConfigExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventL1LoggedMDTConfigExtIEsExtField, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtField, aper.Snapshot)
	compare func(EventL1LoggedMDTConfigExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) New(value EventL1LoggedMDTConfigExtIEsExtField) (EventL1LoggedMDTConfigExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventL1LoggedMDTConfigExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventL1LoggedMDTConfigExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) EncodeAPER(value EventL1LoggedMDTConfigExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) encodeBudgetValue(value EventL1LoggedMDTConfigExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) encodeChanged(value EventL1LoggedMDTConfigExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec is the concrete ValueCodec[ExpectedUEActivityBehaviourExtIEsExtField].
type ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtField, error)
	encode  func(ExpectedUEActivityBehaviourExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ExpectedUEActivityBehaviourExtIEsExtField, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtField, aper.Snapshot)
	compare func(ExpectedUEActivityBehaviourExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) New(value ExpectedUEActivityBehaviourExtIEsExtField) (ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) EncodeAPER(value ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) encodeBudgetValue(value ExpectedUEActivityBehaviourExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) encodeChanged(value ExpectedUEActivityBehaviourExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ExpectedUEBehaviourExtIEsExtFieldValueCodec is the concrete ValueCodec[ExpectedUEBehaviourExtIEsExtField].
type ExpectedUEBehaviourExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtField, error)
	encode  func(ExpectedUEBehaviourExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ExpectedUEBehaviourExtIEsExtField, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtField, aper.Snapshot)
	compare func(ExpectedUEBehaviourExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ExpectedUEBehaviourExtIEsExtFieldValueCodec) New(value ExpectedUEBehaviourExtIEsExtField) (ExpectedUEBehaviourExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ExpectedUEBehaviourExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ExpectedUEBehaviourExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ExpectedUEBehaviourExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ExpectedUEBehaviourExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ExpectedUEBehaviourExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ExpectedUEBehaviourExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ExpectedUEBehaviourExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ExpectedUEBehaviourExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ExpectedUEBehaviourExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ExpectedUEBehaviourExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ExpectedUEBehaviourExtIEsExtFieldValueCodec) EncodeAPER(value ExpectedUEBehaviourExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ExpectedUEBehaviourExtIEsExtFieldValueCodec) encodeBudgetValue(value ExpectedUEBehaviourExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ExpectedUEBehaviourExtIEsExtFieldValueCodec) encodeChanged(value ExpectedUEBehaviourExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// FiveGSTAIExtIEsExtFieldValueCodec is the concrete ValueCodec[FiveGSTAIExtIEsExtField].
type FiveGSTAIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (FiveGSTAIExtIEsExtField, error)
	encode  func(FiveGSTAIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(FiveGSTAIExtIEsExtField, aper.DecodeState) (FiveGSTAIExtIEsExtField, aper.Snapshot)
	compare func(FiveGSTAIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c FiveGSTAIExtIEsExtFieldValueCodec) New(value FiveGSTAIExtIEsExtField) (FiveGSTAIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return FiveGSTAIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return FiveGSTAIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return FiveGSTAIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return FiveGSTAIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c FiveGSTAIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (FiveGSTAIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return FiveGSTAIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return FiveGSTAIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return FiveGSTAIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return FiveGSTAIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c FiveGSTAIExtIEsExtFieldValueCodec) EncodeAPER(value FiveGSTAIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c FiveGSTAIExtIEsExtFieldValueCodec) encodeBudgetValue(value FiveGSTAIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c FiveGSTAIExtIEsExtFieldValueCodec) encodeChanged(value FiveGSTAIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenLAsItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ForbiddenLAsItemExtIEsExtField].
type ForbiddenLAsItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenLAsItemExtIEsExtField, error)
	encode  func(ForbiddenLAsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenLAsItemExtIEsExtField, aper.DecodeState) (ForbiddenLAsItemExtIEsExtField, aper.Snapshot)
	compare func(ForbiddenLAsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenLAsItemExtIEsExtFieldValueCodec) New(value ForbiddenLAsItemExtIEsExtField) (ForbiddenLAsItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ForbiddenLAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenLAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenLAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenLAsItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenLAsItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenLAsItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenLAsItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenLAsItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenLAsItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenLAsItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenLAsItemExtIEsExtFieldValueCodec) EncodeAPER(value ForbiddenLAsItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenLAsItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ForbiddenLAsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenLAsItemExtIEsExtFieldValueCodec) encodeChanged(value ForbiddenLAsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenTAsItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ForbiddenTAsItemExtIEsExtField].
type ForbiddenTAsItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenTAsItemExtIEsExtField, error)
	encode  func(ForbiddenTAsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenTAsItemExtIEsExtField, aper.DecodeState) (ForbiddenTAsItemExtIEsExtField, aper.Snapshot)
	compare func(ForbiddenTAsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenTAsItemExtIEsExtFieldValueCodec) New(value ForbiddenTAsItemExtIEsExtField) (ForbiddenTAsItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ForbiddenTAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenTAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenTAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenTAsItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenTAsItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenTAsItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenTAsItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenTAsItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenTAsItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenTAsItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenTAsItemExtIEsExtFieldValueCodec) EncodeAPER(value ForbiddenTAsItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenTAsItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ForbiddenTAsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenTAsItemExtIEsExtFieldValueCodec) encodeChanged(value ForbiddenTAsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCTransferTypeRequestExtIEsExtContainerValueCodec is the concrete ValueCodec[ENDCTransferTypeRequestExtIEsExtContainer].
type ENDCTransferTypeRequestExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtContainer, error)
	encode  func(ENDCTransferTypeRequestExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCTransferTypeRequestExtIEsExtContainer, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtContainer, aper.Snapshot)
	compare func(ENDCTransferTypeRequestExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCTransferTypeRequestExtIEsExtContainerValueCodec) New(value ENDCTransferTypeRequestExtIEsExtContainer) (ENDCTransferTypeRequestExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCTransferTypeRequestExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCTransferTypeRequestExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCTransferTypeRequestExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCTransferTypeRequestExtIEsExtContainerValueCodec) EncodeAPER(value ENDCTransferTypeRequestExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCTransferTypeRequestExtIEsExtContainerValueCodec) encodeBudgetValue(value ENDCTransferTypeRequestExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCTransferTypeRequestExtIEsExtContainerValueCodec) encodeChanged(value ENDCTransferTypeRequestExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABAdmittedItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABAdmittedItemExtIEsExtContainer].
type ERABAdmittedItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItemExtIEsExtContainer, error)
	encode  func(ERABAdmittedItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItemExtIEsExtContainer, aper.DecodeState) (ERABAdmittedItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABAdmittedItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemExtIEsExtContainerValueCodec) New(value ERABAdmittedItemExtIEsExtContainer) (ERABAdmittedItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABAdmittedItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABAdmittedItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemExtIEsExtContainerValueCodec) encodeChanged(value ERABAdmittedItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABDataForwardingItemExtIEsExtContainer].
type ERABDataForwardingItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItemExtIEsExtContainer, error)
	encode  func(ERABDataForwardingItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItemExtIEsExtContainer, aper.DecodeState) (ERABDataForwardingItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABDataForwardingItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemExtIEsExtContainerValueCodec) New(value ERABDataForwardingItemExtIEsExtContainer) (ERABDataForwardingItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABDataForwardingItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABDataForwardingItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemExtIEsExtContainerValueCodec) encodeChanged(value ERABDataForwardingItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReqExtIEsExtContainer].
type ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtContainer, error)
	encode  func(ERABFailedToResumeItemResumeReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) New(value ERABFailedToResumeItemResumeReqExtIEsExtContainer) (ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeResExtIEsExtContainer].
type ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtContainer, error)
	encode  func(ERABFailedToResumeItemResumeResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) New(value ERABFailedToResumeItemResumeResExtIEsExtContainer) (ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) encodeChanged(value ERABFailedToResumeItemResumeResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABFailedToSetupItemHOReqAckExtIEsExtContainer].
type ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtContainer, error)
	encode  func(ERABFailedToSetupItemHOReqAckExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.Snapshot)
	compare func(ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) New(value ERABFailedToSetupItemHOReqAckExtIEsExtContainer) (ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) EncodeAPER(value ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABFailedToSetupItemHOReqAckExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) encodeChanged(value ERABFailedToSetupItemHOReqAckExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABItemExtIEsExtContainer].
type ERABItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItemExtIEsExtContainer, error)
	encode  func(ERABItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItemExtIEsExtContainer, aper.DecodeState) (ERABItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemExtIEsExtContainerValueCodec) New(value ERABItemExtIEsExtContainer) (ERABItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemExtIEsExtContainerValueCodec) encodeChanged(value ERABItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABModifyItemBearerModConfExtIEsExtContainer].
type ERABModifyItemBearerModConfExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtContainer, error)
	encode  func(ERABModifyItemBearerModConfExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConfExtIEsExtContainer, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtContainer, aper.Snapshot)
	compare func(ERABModifyItemBearerModConfExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) New(value ERABModifyItemBearerModConfExtIEsExtContainer) (ERABModifyItemBearerModConfExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) EncodeAPER(value ERABModifyItemBearerModConfExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConfExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) encodeChanged(value ERABModifyItemBearerModConfExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABModifyItemBearerModResExtIEsExtContainer].
type ERABModifyItemBearerModResExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtContainer, error)
	encode  func(ERABModifyItemBearerModResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModResExtIEsExtContainer, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtContainer, aper.Snapshot)
	compare func(ERABModifyItemBearerModResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResExtIEsExtContainerValueCodec) New(value ERABModifyItemBearerModResExtIEsExtContainer) (ERABModifyItemBearerModResExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResExtIEsExtContainerValueCodec) EncodeAPER(value ERABModifyItemBearerModResExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABModifyItemBearerModResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResExtIEsExtContainerValueCodec) encodeChanged(value ERABModifyItemBearerModResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer].
type ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, error)
	encode  func(ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot)
	compare func(ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) New(value ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer) (ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABQoSParametersExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABQoSParametersExtIEsExtContainer].
type ERABQoSParametersExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABQoSParametersExtIEsExtContainer, error)
	encode  func(ERABQoSParametersExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABQoSParametersExtIEsExtContainer, aper.DecodeState) (ERABQoSParametersExtIEsExtContainer, aper.Snapshot)
	compare func(ERABQoSParametersExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABQoSParametersExtIEsExtContainerValueCodec) New(value ERABQoSParametersExtIEsExtContainer) (ERABQoSParametersExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABQoSParametersExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABQoSParametersExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABQoSParametersExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABQoSParametersExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABQoSParametersExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABQoSParametersExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABQoSParametersExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABQoSParametersExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABQoSParametersExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABQoSParametersExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABQoSParametersExtIEsExtContainerValueCodec) EncodeAPER(value ERABQoSParametersExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABQoSParametersExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABQoSParametersExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABQoSParametersExtIEsExtContainerValueCodec) encodeChanged(value ERABQoSParametersExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABReleaseItemBearerRelCompExtIEsExtContainer].
type ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtContainer, error)
	encode  func(ERABReleaseItemBearerRelCompExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.Snapshot)
	compare func(ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) New(value ERABReleaseItemBearerRelCompExtIEsExtContainer) (ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelCompExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) encodeChanged(value ERABReleaseItemBearerRelCompExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSecurityResultItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABSecurityResultItemExtIEsExtContainer].
type ERABSecurityResultItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSecurityResultItemExtIEsExtContainer, error)
	encode  func(ERABSecurityResultItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSecurityResultItemExtIEsExtContainer, aper.DecodeState) (ERABSecurityResultItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABSecurityResultItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSecurityResultItemExtIEsExtContainerValueCodec) New(value ERABSecurityResultItemExtIEsExtContainer) (ERABSecurityResultItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSecurityResultItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSecurityResultItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSecurityResultItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSecurityResultItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSecurityResultItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSecurityResultItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSecurityResultItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSecurityResultItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSecurityResultItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSecurityResultItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSecurityResultItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABSecurityResultItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSecurityResultItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABSecurityResultItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSecurityResultItemExtIEsExtContainerValueCodec) encodeChanged(value ERABSecurityResultItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABSetupItemBearerSUResExtIEsExtContainer].
type ERABSetupItemBearerSUResExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtContainer, error)
	encode  func(ERABSetupItemBearerSUResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSUResExtIEsExtContainer, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtContainer, aper.Snapshot)
	compare func(ERABSetupItemBearerSUResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) New(value ERABSetupItemBearerSUResExtIEsExtContainer) (ERABSetupItemBearerSUResExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) EncodeAPER(value ERABSetupItemBearerSUResExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABSetupItemBearerSUResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) encodeChanged(value ERABSetupItemBearerSUResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABSetupItemCtxtSUResExtIEsExtContainer].
type ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtContainer, error)
	encode  func(ERABSetupItemCtxtSUResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSUResExtIEsExtContainer, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtContainer, aper.Snapshot)
	compare func(ERABSetupItemCtxtSUResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) New(value ERABSetupItemCtxtSUResExtIEsExtContainer) (ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSUResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) encodeChanged(value ERABSetupItemCtxtSUResExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModIndExtIEsExtContainer].
type ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtContainer, error)
	encode  func(ERABToBeModifiedItemBearerModIndExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) New(value ERABToBeModifiedItemBearerModIndExtIEsExtContainer) (ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItemExtIEsExtContainer].
type ERABToBeSwitchedULItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtContainer, error)
	encode  func(ERABToBeSwitchedULItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItemExtIEsExtContainer, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeSwitchedULItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) New(value ERABToBeSwitchedULItemExtIEsExtContainer) (ERABToBeSwitchedULItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeSwitchedULItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeSwitchedULItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeUpdatedItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeUpdatedItemExtIEsExtContainer].
type ERABToBeUpdatedItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtContainer, error)
	encode  func(ERABToBeUpdatedItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeUpdatedItemExtIEsExtContainer, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeUpdatedItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeUpdatedItemExtIEsExtContainerValueCodec) New(value ERABToBeUpdatedItemExtIEsExtContainer) (ERABToBeUpdatedItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeUpdatedItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeUpdatedItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeUpdatedItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeUpdatedItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeUpdatedItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeUpdatedItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeUpdatedItemExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeUpdatedItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABUsageReportItemExtIEsExtContainer].
type ERABUsageReportItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItemExtIEsExtContainer, error)
	encode  func(ERABUsageReportItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItemExtIEsExtContainer, aper.DecodeState) (ERABUsageReportItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABUsageReportItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemExtIEsExtContainerValueCodec) New(value ERABUsageReportItemExtIEsExtContainer) (ERABUsageReportItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABUsageReportItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABUsageReportItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemExtIEsExtContainerValueCodec) encodeChanged(value ERABUsageReportItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EUTRANCGIExtIEsExtContainerValueCodec is the concrete ValueCodec[EUTRANCGIExtIEsExtContainer].
type EUTRANCGIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EUTRANCGIExtIEsExtContainer, error)
	encode  func(EUTRANCGIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EUTRANCGIExtIEsExtContainer, aper.DecodeState) (EUTRANCGIExtIEsExtContainer, aper.Snapshot)
	compare func(EUTRANCGIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EUTRANCGIExtIEsExtContainerValueCodec) New(value EUTRANCGIExtIEsExtContainer) (EUTRANCGIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return EUTRANCGIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EUTRANCGIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANCGIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EUTRANCGIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EUTRANCGIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EUTRANCGIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EUTRANCGIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EUTRANCGIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EUTRANCGIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EUTRANCGIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EUTRANCGIExtIEsExtContainerValueCodec) EncodeAPER(value EUTRANCGIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EUTRANCGIExtIEsExtContainerValueCodec) encodeBudgetValue(value EUTRANCGIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EUTRANCGIExtIEsExtContainerValueCodec) encodeChanged(value EUTRANCGIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec is the concrete ValueCodec[EmergencyAreaIDBroadcastItemExtIEsExtContainer].
type EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtContainer, error)
	encode  func(EmergencyAreaIDBroadcastItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.Snapshot)
	compare func(EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) New(value EmergencyAreaIDBroadcastItemExtIEsExtContainer) (EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) EncodeAPER(value EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) encodeBudgetValue(value EmergencyAreaIDBroadcastItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) encodeChanged(value EmergencyAreaIDBroadcastItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec is the concrete ValueCodec[EmergencyAreaIDCancelledItemExtIEsExtContainer].
type EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtContainer, error)
	encode  func(EmergencyAreaIDCancelledItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.Snapshot)
	compare func(EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) New(value EmergencyAreaIDCancelledItemExtIEsExtContainer) (EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) EncodeAPER(value EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) encodeBudgetValue(value EmergencyAreaIDCancelledItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) encodeChanged(value EmergencyAreaIDCancelledItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventL1LoggedMDTConfigExtIEsExtContainerValueCodec is the concrete ValueCodec[EventL1LoggedMDTConfigExtIEsExtContainer].
type EventL1LoggedMDTConfigExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtContainer, error)
	encode  func(EventL1LoggedMDTConfigExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventL1LoggedMDTConfigExtIEsExtContainer, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtContainer, aper.Snapshot)
	compare func(EventL1LoggedMDTConfigExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) New(value EventL1LoggedMDTConfigExtIEsExtContainer) (EventL1LoggedMDTConfigExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventL1LoggedMDTConfigExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventL1LoggedMDTConfigExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) EncodeAPER(value EventL1LoggedMDTConfigExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) encodeBudgetValue(value EventL1LoggedMDTConfigExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) encodeChanged(value EventL1LoggedMDTConfigExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec is the concrete ValueCodec[ExpectedUEActivityBehaviourExtIEsExtContainer].
type ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtContainer, error)
	encode  func(ExpectedUEActivityBehaviourExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ExpectedUEActivityBehaviourExtIEsExtContainer, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtContainer, aper.Snapshot)
	compare func(ExpectedUEActivityBehaviourExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) New(value ExpectedUEActivityBehaviourExtIEsExtContainer) (ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) EncodeAPER(value ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) encodeBudgetValue(value ExpectedUEActivityBehaviourExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) encodeChanged(value ExpectedUEActivityBehaviourExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ExpectedUEBehaviourExtIEsExtContainerValueCodec is the concrete ValueCodec[ExpectedUEBehaviourExtIEsExtContainer].
type ExpectedUEBehaviourExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtContainer, error)
	encode  func(ExpectedUEBehaviourExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ExpectedUEBehaviourExtIEsExtContainer, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtContainer, aper.Snapshot)
	compare func(ExpectedUEBehaviourExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ExpectedUEBehaviourExtIEsExtContainerValueCodec) New(value ExpectedUEBehaviourExtIEsExtContainer) (ExpectedUEBehaviourExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ExpectedUEBehaviourExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ExpectedUEBehaviourExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ExpectedUEBehaviourExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ExpectedUEBehaviourExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ExpectedUEBehaviourExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ExpectedUEBehaviourExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ExpectedUEBehaviourExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ExpectedUEBehaviourExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ExpectedUEBehaviourExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ExpectedUEBehaviourExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ExpectedUEBehaviourExtIEsExtContainerValueCodec) EncodeAPER(value ExpectedUEBehaviourExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ExpectedUEBehaviourExtIEsExtContainerValueCodec) encodeBudgetValue(value ExpectedUEBehaviourExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ExpectedUEBehaviourExtIEsExtContainerValueCodec) encodeChanged(value ExpectedUEBehaviourExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// FiveGSTAIExtIEsExtContainerValueCodec is the concrete ValueCodec[FiveGSTAIExtIEsExtContainer].
type FiveGSTAIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (FiveGSTAIExtIEsExtContainer, error)
	encode  func(FiveGSTAIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(FiveGSTAIExtIEsExtContainer, aper.DecodeState) (FiveGSTAIExtIEsExtContainer, aper.Snapshot)
	compare func(FiveGSTAIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c FiveGSTAIExtIEsExtContainerValueCodec) New(value FiveGSTAIExtIEsExtContainer) (FiveGSTAIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return FiveGSTAIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return FiveGSTAIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return FiveGSTAIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return FiveGSTAIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c FiveGSTAIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (FiveGSTAIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return FiveGSTAIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return FiveGSTAIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return FiveGSTAIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return FiveGSTAIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c FiveGSTAIExtIEsExtContainerValueCodec) EncodeAPER(value FiveGSTAIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c FiveGSTAIExtIEsExtContainerValueCodec) encodeBudgetValue(value FiveGSTAIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c FiveGSTAIExtIEsExtContainerValueCodec) encodeChanged(value FiveGSTAIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenLAsItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ForbiddenLAsItemExtIEsExtContainer].
type ForbiddenLAsItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenLAsItemExtIEsExtContainer, error)
	encode  func(ForbiddenLAsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenLAsItemExtIEsExtContainer, aper.DecodeState) (ForbiddenLAsItemExtIEsExtContainer, aper.Snapshot)
	compare func(ForbiddenLAsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenLAsItemExtIEsExtContainerValueCodec) New(value ForbiddenLAsItemExtIEsExtContainer) (ForbiddenLAsItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ForbiddenLAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenLAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenLAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenLAsItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenLAsItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenLAsItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenLAsItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenLAsItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenLAsItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenLAsItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenLAsItemExtIEsExtContainerValueCodec) EncodeAPER(value ForbiddenLAsItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenLAsItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ForbiddenLAsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenLAsItemExtIEsExtContainerValueCodec) encodeChanged(value ForbiddenLAsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenTAsItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ForbiddenTAsItemExtIEsExtContainer].
type ForbiddenTAsItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenTAsItemExtIEsExtContainer, error)
	encode  func(ForbiddenTAsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenTAsItemExtIEsExtContainer, aper.DecodeState) (ForbiddenTAsItemExtIEsExtContainer, aper.Snapshot)
	compare func(ForbiddenTAsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenTAsItemExtIEsExtContainerValueCodec) New(value ForbiddenTAsItemExtIEsExtContainer) (ForbiddenTAsItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ForbiddenTAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenTAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenTAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenTAsItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenTAsItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenTAsItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenTAsItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenTAsItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenTAsItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenTAsItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenTAsItemExtIEsExtContainerValueCodec) EncodeAPER(value ForbiddenTAsItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenTAsItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ForbiddenTAsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenTAsItemExtIEsExtContainerValueCodec) encodeChanged(value ForbiddenTAsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggerExtIEFieldValueCodec is the concrete ValueCodec[EventTriggerExtIEField].
type EventTriggerExtIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTriggerExtIEField, error)
	encode  func(EventTriggerExtIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTriggerExtIEField, aper.DecodeState) (EventTriggerExtIEField, aper.Snapshot)
	compare func(EventTriggerExtIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggerExtIEFieldValueCodec) New(value EventTriggerExtIEField) (EventTriggerExtIEFieldAPERValue, error) {
	if c.encode == nil {
		return EventTriggerExtIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggerExtIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggerExtIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggerExtIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggerExtIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggerExtIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggerExtIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggerExtIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggerExtIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggerExtIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggerExtIEFieldValueCodec) EncodeAPER(value EventTriggerExtIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventTriggerExtIEFieldValueCodec) encodeBudgetValue(value EventTriggerExtIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggerExtIEFieldValueCodec) encodeChanged(value EventTriggerExtIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggerExtIEContainerValueCodec is the concrete ValueCodec[EventTriggerExtIEContainer].
type EventTriggerExtIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTriggerExtIEContainer, error)
	encode  func(EventTriggerExtIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTriggerExtIEContainer, aper.DecodeState) (EventTriggerExtIEContainer, aper.Snapshot)
	compare func(EventTriggerExtIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggerExtIEContainerValueCodec) New(value EventTriggerExtIEContainer) (EventTriggerExtIEContainerAPERValue, error) {
	if c.encode == nil {
		return EventTriggerExtIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggerExtIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggerExtIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggerExtIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggerExtIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggerExtIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggerExtIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggerExtIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggerExtIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggerExtIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggerExtIEContainerValueCodec) EncodeAPER(value EventTriggerExtIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventTriggerExtIEContainerValueCodec) encodeBudgetValue(value EventTriggerExtIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggerExtIEContainerValueCodec) encodeChanged(value EventTriggerExtIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[EventTriggerExtIEValueProtocolErrorIEContainerList].
type EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTriggerExtIEValueProtocolErrorIEContainerList, error)
	encode  func(EventTriggerExtIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTriggerExtIEValueProtocolErrorIEContainerList, aper.DecodeState) (EventTriggerExtIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(EventTriggerExtIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) New(value EventTriggerExtIEValueProtocolErrorIEContainerList) (EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value EventTriggerExtIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value EventTriggerExtIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggerExtIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{EventTrigger-ExtIEs}} of TS 36.413: a list of information element fields.
type EventTriggerExtIEValueProtocolErrorIEContainerList []EventTriggerExtIEValueProtocolIESingleContainer

// EventTriggerExtIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[EventTriggerExtIEValueProtocolIEContainerList].
type EventTriggerExtIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTriggerExtIEValueProtocolIEContainerList, error)
	encode  func(EventTriggerExtIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTriggerExtIEValueProtocolIEContainerList, aper.DecodeState) (EventTriggerExtIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(EventTriggerExtIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggerExtIEValueProtocolIEContainerListValueCodec) New(value EventTriggerExtIEValueProtocolIEContainerList) (EventTriggerExtIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return EventTriggerExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggerExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggerExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggerExtIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggerExtIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggerExtIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggerExtIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggerExtIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggerExtIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggerExtIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggerExtIEValueProtocolIEContainerListValueCodec) EncodeAPER(value EventTriggerExtIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventTriggerExtIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value EventTriggerExtIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggerExtIEValueProtocolIEContainerListValueCodec) encodeChanged(value EventTriggerExtIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggerExtIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {EventTrigger-ExtIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type EventTriggerExtIEValueProtocolIEContainerList []EventTriggerExtIEValueProtocolIESingleContainer

// EventTriggerExtIEValueERABIEContainerListAPERValue is the concrete APERValue[EventTriggerExtIEValueERABIEContainerList].
type EventTriggerExtIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EventTriggerExtIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggerExtIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggerExtIEValueERABIEContainerListAPERValue) WithoutReplay() EventTriggerExtIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCTransferTypeRequestExtIEsExtFieldAPERValue is the concrete APERValue[ENDCTransferTypeRequestExtIEsExtField].
type ENDCTransferTypeRequestExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCTransferTypeRequestExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCTransferTypeRequestExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeRequestExtIEsExtFieldAPERValue) WithoutReplay() ENDCTransferTypeRequestExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABAdmittedItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABAdmittedItemExtIEsExtField].
type ERABAdmittedItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABAdmittedItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemExtIEsExtFieldAPERValue) WithoutReplay() ERABAdmittedItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABDataForwardingItemExtIEsExtField].
type ERABDataForwardingItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABDataForwardingItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemExtIEsExtFieldAPERValue) WithoutReplay() ERABDataForwardingItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReqExtIEsExtField].
type ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeResExtIEsExtField].
type ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeResExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue) WithoutReplay() ERABFailedToResumeItemResumeResExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue is the concrete APERValue[ERABFailedToSetupItemHOReqAckExtIEsExtField].
type ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToSetupItemHOReqAckExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue) WithoutReplay() ERABFailedToSetupItemHOReqAckExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABItemExtIEsExtField].
type ERABItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemExtIEsExtFieldAPERValue) WithoutReplay() ERABItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfExtIEsExtFieldAPERValue is the concrete APERValue[ERABModifyItemBearerModConfExtIEsExtField].
type ERABModifyItemBearerModConfExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModConfExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfExtIEsExtFieldAPERValue) WithoutReplay() ERABModifyItemBearerModConfExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResExtIEsExtFieldAPERValue is the concrete APERValue[ERABModifyItemBearerModResExtIEsExtField].
type ERABModifyItemBearerModResExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModResExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResExtIEsExtFieldAPERValue) WithoutReplay() ERABModifyItemBearerModResExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue is the concrete APERValue[ERABNotToBeModifiedItemBearerModIndExtIEsExtField].
type ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABNotToBeModifiedItemBearerModIndExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABQoSParametersExtIEsExtFieldAPERValue is the concrete APERValue[ERABQoSParametersExtIEsExtField].
type ERABQoSParametersExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABQoSParametersExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABQoSParametersExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABQoSParametersExtIEsExtFieldAPERValue) WithoutReplay() ERABQoSParametersExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue is the concrete APERValue[ERABReleaseItemBearerRelCompExtIEsExtField].
type ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseItemBearerRelCompExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSecurityResultItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABSecurityResultItemExtIEsExtField].
type ERABSecurityResultItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSecurityResultItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultItemExtIEsExtFieldAPERValue) WithoutReplay() ERABSecurityResultItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResExtIEsExtFieldAPERValue is the concrete APERValue[ERABSetupItemBearerSUResExtIEsExtField].
type ERABSetupItemBearerSUResExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemBearerSUResExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResExtIEsExtFieldAPERValue) WithoutReplay() ERABSetupItemBearerSUResExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue is the concrete APERValue[ERABSetupItemCtxtSUResExtIEsExtField].
type ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemCtxtSUResExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue) WithoutReplay() ERABSetupItemCtxtSUResExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModIndExtIEsExtField].
type ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModIndExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeSwitchedULItemExtIEsExtField].
type ERABToBeSwitchedULItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedULItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeSwitchedULItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeUpdatedItemExtIEsExtField].
type ERABToBeUpdatedItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeUpdatedItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeUpdatedItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABUsageReportItemExtIEsExtField].
type ERABUsageReportItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABUsageReportItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemExtIEsExtFieldAPERValue) WithoutReplay() ERABUsageReportItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANCGIExtIEsExtFieldAPERValue is the concrete APERValue[EUTRANCGIExtIEsExtField].
type EUTRANCGIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EUTRANCGIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EUTRANCGIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EUTRANCGIExtIEsExtFieldAPERValue) WithoutReplay() EUTRANCGIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue is the concrete APERValue[EmergencyAreaIDBroadcastItemExtIEsExtField].
type EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EmergencyAreaIDBroadcastItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue) WithoutReplay() EmergencyAreaIDBroadcastItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue is the concrete APERValue[EmergencyAreaIDCancelledItemExtIEsExtField].
type EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EmergencyAreaIDCancelledItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue) WithoutReplay() EmergencyAreaIDCancelledItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventL1LoggedMDTConfigExtIEsExtFieldAPERValue is the concrete APERValue[EventL1LoggedMDTConfigExtIEsExtField].
type EventL1LoggedMDTConfigExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EventL1LoggedMDTConfigExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventL1LoggedMDTConfigExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventL1LoggedMDTConfigExtIEsExtFieldAPERValue) WithoutReplay() EventL1LoggedMDTConfigExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue is the concrete APERValue[ExpectedUEActivityBehaviourExtIEsExtField].
type ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ExpectedUEActivityBehaviourExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue) WithoutReplay() ExpectedUEActivityBehaviourExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ExpectedUEBehaviourExtIEsExtFieldAPERValue is the concrete APERValue[ExpectedUEBehaviourExtIEsExtField].
type ExpectedUEBehaviourExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ExpectedUEBehaviourExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ExpectedUEBehaviourExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEBehaviourExtIEsExtFieldAPERValue) WithoutReplay() ExpectedUEBehaviourExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// FiveGSTAIExtIEsExtFieldAPERValue is the concrete APERValue[FiveGSTAIExtIEsExtField].
type FiveGSTAIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         FiveGSTAIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v FiveGSTAIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FiveGSTAIExtIEsExtFieldAPERValue) WithoutReplay() FiveGSTAIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenLAsItemExtIEsExtFieldAPERValue is the concrete APERValue[ForbiddenLAsItemExtIEsExtField].
type ForbiddenLAsItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ForbiddenLAsItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenLAsItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenLAsItemExtIEsExtFieldAPERValue) WithoutReplay() ForbiddenLAsItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenTAsItemExtIEsExtFieldAPERValue is the concrete APERValue[ForbiddenTAsItemExtIEsExtField].
type ForbiddenTAsItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ForbiddenTAsItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenTAsItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenTAsItemExtIEsExtFieldAPERValue) WithoutReplay() ForbiddenTAsItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCTransferTypeRequestExtIEsExtContainerAPERValue is the concrete APERValue[ENDCTransferTypeRequestExtIEsExtContainer].
type ENDCTransferTypeRequestExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCTransferTypeRequestExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCTransferTypeRequestExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeRequestExtIEsExtContainerAPERValue) WithoutReplay() ENDCTransferTypeRequestExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABAdmittedItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABAdmittedItemExtIEsExtContainer].
type ERABAdmittedItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABAdmittedItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemExtIEsExtContainerAPERValue) WithoutReplay() ERABAdmittedItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABDataForwardingItemExtIEsExtContainer].
type ERABDataForwardingItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABDataForwardingItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemExtIEsExtContainerAPERValue) WithoutReplay() ERABDataForwardingItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReqExtIEsExtContainer].
type ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeResExtIEsExtContainer].
type ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeResExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue) WithoutReplay() ERABFailedToResumeItemResumeResExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue is the concrete APERValue[ERABFailedToSetupItemHOReqAckExtIEsExtContainer].
type ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToSetupItemHOReqAckExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue) WithoutReplay() ERABFailedToSetupItemHOReqAckExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABItemExtIEsExtContainer].
type ERABItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemExtIEsExtContainerAPERValue) WithoutReplay() ERABItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfExtIEsExtContainerAPERValue is the concrete APERValue[ERABModifyItemBearerModConfExtIEsExtContainer].
type ERABModifyItemBearerModConfExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModConfExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfExtIEsExtContainerAPERValue) WithoutReplay() ERABModifyItemBearerModConfExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResExtIEsExtContainerAPERValue is the concrete APERValue[ERABModifyItemBearerModResExtIEsExtContainer].
type ERABModifyItemBearerModResExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModResExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResExtIEsExtContainerAPERValue) WithoutReplay() ERABModifyItemBearerModResExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue is the concrete APERValue[ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer].
type ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABQoSParametersExtIEsExtContainerAPERValue is the concrete APERValue[ERABQoSParametersExtIEsExtContainer].
type ERABQoSParametersExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABQoSParametersExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABQoSParametersExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABQoSParametersExtIEsExtContainerAPERValue) WithoutReplay() ERABQoSParametersExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue is the concrete APERValue[ERABReleaseItemBearerRelCompExtIEsExtContainer].
type ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseItemBearerRelCompExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSecurityResultItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABSecurityResultItemExtIEsExtContainer].
type ERABSecurityResultItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSecurityResultItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSecurityResultItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSecurityResultItemExtIEsExtContainerAPERValue) WithoutReplay() ERABSecurityResultItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResExtIEsExtContainerAPERValue is the concrete APERValue[ERABSetupItemBearerSUResExtIEsExtContainer].
type ERABSetupItemBearerSUResExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemBearerSUResExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResExtIEsExtContainerAPERValue) WithoutReplay() ERABSetupItemBearerSUResExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue is the concrete APERValue[ERABSetupItemCtxtSUResExtIEsExtContainer].
type ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemCtxtSUResExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue) WithoutReplay() ERABSetupItemCtxtSUResExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModIndExtIEsExtContainer].
type ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModIndExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeSwitchedULItemExtIEsExtContainer].
type ERABToBeSwitchedULItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedULItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeSwitchedULItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeUpdatedItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeUpdatedItemExtIEsExtContainer].
type ERABToBeUpdatedItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeUpdatedItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeUpdatedItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeUpdatedItemExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeUpdatedItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportItemExtIEsExtContainerAPERValue is the concrete APERValue[ERABUsageReportItemExtIEsExtContainer].
type ERABUsageReportItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABUsageReportItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemExtIEsExtContainerAPERValue) WithoutReplay() ERABUsageReportItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANCGIExtIEsExtContainerAPERValue is the concrete APERValue[EUTRANCGIExtIEsExtContainer].
type EUTRANCGIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EUTRANCGIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EUTRANCGIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EUTRANCGIExtIEsExtContainerAPERValue) WithoutReplay() EUTRANCGIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue is the concrete APERValue[EmergencyAreaIDBroadcastItemExtIEsExtContainer].
type EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EmergencyAreaIDBroadcastItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue) WithoutReplay() EmergencyAreaIDBroadcastItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue is the concrete APERValue[EmergencyAreaIDCancelledItemExtIEsExtContainer].
type EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EmergencyAreaIDCancelledItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue) WithoutReplay() EmergencyAreaIDCancelledItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventL1LoggedMDTConfigExtIEsExtContainerAPERValue is the concrete APERValue[EventL1LoggedMDTConfigExtIEsExtContainer].
type EventL1LoggedMDTConfigExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EventL1LoggedMDTConfigExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventL1LoggedMDTConfigExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventL1LoggedMDTConfigExtIEsExtContainerAPERValue) WithoutReplay() EventL1LoggedMDTConfigExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue is the concrete APERValue[ExpectedUEActivityBehaviourExtIEsExtContainer].
type ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ExpectedUEActivityBehaviourExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue) WithoutReplay() ExpectedUEActivityBehaviourExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ExpectedUEBehaviourExtIEsExtContainerAPERValue is the concrete APERValue[ExpectedUEBehaviourExtIEsExtContainer].
type ExpectedUEBehaviourExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ExpectedUEBehaviourExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ExpectedUEBehaviourExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEBehaviourExtIEsExtContainerAPERValue) WithoutReplay() ExpectedUEBehaviourExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// FiveGSTAIExtIEsExtContainerAPERValue is the concrete APERValue[FiveGSTAIExtIEsExtContainer].
type FiveGSTAIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         FiveGSTAIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v FiveGSTAIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FiveGSTAIExtIEsExtContainerAPERValue) WithoutReplay() FiveGSTAIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenLAsItemExtIEsExtContainerAPERValue is the concrete APERValue[ForbiddenLAsItemExtIEsExtContainer].
type ForbiddenLAsItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ForbiddenLAsItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenLAsItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenLAsItemExtIEsExtContainerAPERValue) WithoutReplay() ForbiddenLAsItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenTAsItemExtIEsExtContainerAPERValue is the concrete APERValue[ForbiddenTAsItemExtIEsExtContainer].
type ForbiddenTAsItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ForbiddenTAsItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenTAsItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenTAsItemExtIEsExtContainerAPERValue) WithoutReplay() ForbiddenTAsItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventTriggerExtIEFieldAPERValue is the concrete APERValue[EventTriggerExtIEField].
type EventTriggerExtIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EventTriggerExtIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggerExtIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggerExtIEFieldAPERValue) WithoutReplay() EventTriggerExtIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventTriggerExtIEContainerAPERValue is the concrete APERValue[EventTriggerExtIEContainer].
type EventTriggerExtIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EventTriggerExtIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggerExtIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggerExtIEContainerAPERValue) WithoutReplay() EventTriggerExtIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[EventTriggerExtIEValueProtocolErrorIEContainerList].
type EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EventTriggerExtIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() EventTriggerExtIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventTriggerExtIEValueProtocolIEContainerListAPERValue is the concrete APERValue[EventTriggerExtIEValueProtocolIEContainerList].
type EventTriggerExtIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         EventTriggerExtIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggerExtIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggerExtIEValueProtocolIEContainerListAPERValue) WithoutReplay() EventTriggerExtIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABQoSParametersExtIEsValue(v *ERABQoSParametersExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(273):
			{
				f := s.Begin()
				s.Bool(v.rowDownlinkPacketLossRate == nil)
				if v.rowDownlinkPacketLossRate != nil {
					s00.BridgeCaptureS1APPacketLossRate(v.rowDownlinkPacketLossRate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(274):
			{
				f := s.Begin()
				s.Bool(v.rowUplinkPacketLossRate == nil)
				if v.rowUplinkPacketLossRate != nil {
					s00.BridgeCaptureS1APPacketLossRate(v.rowUplinkPacketLossRate, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABQoSParametersExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABQoSParametersExtIEsValue {
	BridgeCaptureS1APERABQoSParametersExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABQoSParametersExtIEsValue(v *ERABQoSParametersExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(273):
			{
				f := s.Begin()
				s.Bool(v.rowDownlinkPacketLossRate == nil)
				if v.rowDownlinkPacketLossRate != nil {
					s02.BridgeCompareS1APPacketLossRate(v.rowDownlinkPacketLossRate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(274):
			{
				f := s.Begin()
				s.Bool(v.rowUplinkPacketLossRate == nil)
				if v.rowUplinkPacketLossRate != nil {
					s02.BridgeCompareS1APPacketLossRate(v.rowUplinkPacketLossRate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABQoSParametersExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABQoSParametersExtIEsValue(&v, &s)
	return s
}

type ERABQoSParametersExtIEsValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowDownlinkPacketLossRate *s00.PacketLossRate
	rowUplinkPacketLossRate   *s00.PacketLossRate
}

func (v ERABQoSParametersExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(273):
		return v.rowDownlinkPacketLossRate != nil
	case s00.ProtocolIEID(274):
		return v.rowUplinkPacketLossRate != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABQoSParametersExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABQoSParametersExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABQoSParametersExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABQoSParameters-ExtIEs"}}
}
func (ERABQoSParametersExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(273):
		return aper.UnknownSelector
	case s00.ProtocolIEID(274):
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

// AsDownlinkPacketLossRate returns the selected DownlinkPacketLossRate value of ERABQoSParametersExtIEsValue and reports whether that alternative is active.
func (v *ERABQoSParametersExtIEsValue) AsDownlinkPacketLossRate() (*s00.PacketLossRate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(273) || v.rowDownlinkPacketLossRate == nil {
		return nil, false
	}
	return v.rowDownlinkPacketLossRate, true
}

// AsUplinkPacketLossRate returns the selected UplinkPacketLossRate value of ERABQoSParametersExtIEsValue and reports whether that alternative is active.
func (v *ERABQoSParametersExtIEsValue) AsUplinkPacketLossRate() (*s00.PacketLossRate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(274) || v.rowUplinkPacketLossRate == nil {
		return nil, false
	}
	return v.rowUplinkPacketLossRate, true
}
func (v ERABQoSParametersExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABQoSParametersExtIEsValue, error) {
	out := ERABQoSParametersExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(273):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1000), false)
		value := s00.PacketLossRate(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DownlinkPacketLossRate:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDownlinkPacketLossRate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(274):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1000), false)
		value := s00.PacketLossRate(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UplinkPacketLossRate:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUplinkPacketLossRate = &value
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
func (v ERABQoSParametersExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABQoSParametersExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(273):
		if v.rowDownlinkPacketLossRate == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABQoSParameters-ExtIEs.id-DownlinkPacketLossRate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowDownlinkPacketLossRate), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1000), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(274):
		if v.rowUplinkPacketLossRate == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABQoSParameters-ExtIEs.id-UplinkPacketLossRate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowUplinkPacketLossRate), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1000), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABQoSParametersExtIEsValue:", v.id)
	}
}

type ERABItemExtIETable struct{}

func ERABItemExtIEs() ERABItemExtIETable { return ERABItemExtIETable{} }

// ID returns the ASN.1 object-set identity of ERABItemExtIETable.
func (ERABItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABItemExtIETable.
func (ERABItemExtIETable) Table() s00.ERABItemExtIEsValueExtensionTable {
	return func() s00.ERABItemExtIEsValueExtensionTable {
		sealed := s00.ERABItemExtIEsValueExtensionTable{}
		*s00.BridgeERABItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABItemExtIETable.
func (t ERABItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABItemExtIEsValue {
			sealed := s04.ERABItemExtIEsValue{}
			*s04.BridgeERABItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABQoSParametersExtIETable struct{}

func ERABQoSParametersExtIEs() ERABQoSParametersExtIETable { return ERABQoSParametersExtIETable{} }

// ID returns the ASN.1 object-set identity of ERABQoSParametersExtIETable.
func (ERABQoSParametersExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABQoSParameters-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABQoSParametersExtIETable.
func (ERABQoSParametersExtIETable) Table() s00.ERABQoSParametersExtIEsValueExtensionTable {
	return func() s00.ERABQoSParametersExtIEsValueExtensionTable {
		sealed := s00.ERABQoSParametersExtIEsValueExtensionTable{}
		*s00.BridgeERABQoSParametersExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABQoSParametersExtIETable) infoDownlinkPacketLossRate() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABQoSParametersExtIEs().ID(), ID: s00.ProtocolExtensionID(273), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Packet-LossRate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABQoSParameters-ExtIEs", Row: "id-DownlinkPacketLossRate"}}}
}

// DownlinkPacketLossRate returns the typed binding for the DownlinkPacketLossRate row of ERABQoSParametersExtIETable.
func (t ERABQoSParametersExtIETable) DownlinkPacketLossRate() ERABQoSParametersExtIEsPacketLossRateExtBinding {
	return ERABQoSParametersExtIEsPacketLossRateExtBinding{info: t.infoDownlinkPacketLossRate(), codec: func() s01.PacketLossRateValueCodec {
		sealed := s01.PacketLossRateValueCodec{}
		*s01.BridgePacketLossRateValueCodecFieldPath(&sealed) = "PacketLossRate"
		*s01.BridgePacketLossRateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PacketLossRate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PacketLossRate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PacketLossRate")
			var zero ERABQoSParametersExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(273), raw)
			if err != nil {
				var empty s00.PacketLossRate
				return empty, runtime.WrapDecodePath(err, "PacketLossRate")
			}
			value, ok := decoded.AsDownlinkPacketLossRate()
			if !ok {
				var empty s00.PacketLossRate
				return empty, fmt.Errorf("binding E-RABQoSParameters-ExtIEs.id-DownlinkPacketLossRate: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePacketLossRateValueCodecFieldEncode(&sealed) = func(value s00.PacketLossRate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABQoSParametersExtIEsValue{id: s00.ProtocolIEID(273), rowDownlinkPacketLossRate: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePacketLossRateValueCodecFieldCapture(&sealed) = func(v s00.PacketLossRate, options aper.DecodeState) (s00.PacketLossRate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPacketLossRate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePacketLossRateValueCodecFieldCompare(&sealed) = func(v s00.PacketLossRate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPacketLossRate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePacketLossRateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PacketLossRate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PacketLossRate) ERABQoSParametersExtIEsValue {
			return ERABQoSParametersExtIEsValue{id: s00.ProtocolIEID(273), rowDownlinkPacketLossRate: &value}
		}, get: func(value *ERABQoSParametersExtIEsValue) (*s00.PacketLossRate, bool) {
			return value.AsDownlinkPacketLossRate()
		}}
}
func (ERABQoSParametersExtIETable) infoUplinkPacketLossRate() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABQoSParametersExtIEs().ID(), ID: s00.ProtocolExtensionID(274), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Packet-LossRate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABQoSParameters-ExtIEs", Row: "id-UplinkPacketLossRate"}}}
}

// UplinkPacketLossRate returns the typed binding for the UplinkPacketLossRate row of ERABQoSParametersExtIETable.
func (t ERABQoSParametersExtIETable) UplinkPacketLossRate() ERABQoSParametersExtIEsPacketLossRateExtBinding {
	return ERABQoSParametersExtIEsPacketLossRateExtBinding{info: t.infoUplinkPacketLossRate(), codec: func() s01.PacketLossRateValueCodec {
		sealed := s01.PacketLossRateValueCodec{}
		*s01.BridgePacketLossRateValueCodecFieldPath(&sealed) = "PacketLossRate"
		*s01.BridgePacketLossRateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PacketLossRate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PacketLossRate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PacketLossRate")
			var zero ERABQoSParametersExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(274), raw)
			if err != nil {
				var empty s00.PacketLossRate
				return empty, runtime.WrapDecodePath(err, "PacketLossRate")
			}
			value, ok := decoded.AsUplinkPacketLossRate()
			if !ok {
				var empty s00.PacketLossRate
				return empty, fmt.Errorf("binding E-RABQoSParameters-ExtIEs.id-UplinkPacketLossRate: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePacketLossRateValueCodecFieldEncode(&sealed) = func(value s00.PacketLossRate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABQoSParametersExtIEsValue{id: s00.ProtocolIEID(274), rowUplinkPacketLossRate: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePacketLossRateValueCodecFieldCapture(&sealed) = func(v s00.PacketLossRate, options aper.DecodeState) (s00.PacketLossRate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPacketLossRate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePacketLossRateValueCodecFieldCompare(&sealed) = func(v s00.PacketLossRate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPacketLossRate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePacketLossRateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PacketLossRate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PacketLossRate) ERABQoSParametersExtIEsValue {
			return ERABQoSParametersExtIEsValue{id: s00.ProtocolIEID(274), rowUplinkPacketLossRate: &value}
		}, get: func(value *ERABQoSParametersExtIEsValue) (*s00.PacketLossRate, bool) {
			return value.AsUplinkPacketLossRate()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABQoSParametersExtIETable.
func (t ERABQoSParametersExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABQoSParametersExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABQoSParametersExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(273):
		return ERABQoSParametersExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DownlinkPacketLossRate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(274):
		return ERABQoSParametersExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-UplinkPacketLossRate requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABQoSParametersExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABQoSParametersExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABQoSParametersExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABQoSParametersExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSecurityResultItemExtIETable struct{}

func ERABSecurityResultItemExtIEs() ERABSecurityResultItemExtIETable {
	return ERABSecurityResultItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABSecurityResultItemExtIETable.
func (ERABSecurityResultItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABSecurityResultItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSecurityResultItemExtIETable.
func (ERABSecurityResultItemExtIETable) Table() s00.ERABSecurityResultItemExtIEsValueExtensionTable {
	return func() s00.ERABSecurityResultItemExtIEsValueExtensionTable {
		sealed := s00.ERABSecurityResultItemExtIEsValueExtensionTable{}
		*s00.BridgeERABSecurityResultItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSecurityResultItemExtIETable.
func (t ERABSecurityResultItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABSecurityResultItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSecurityResultItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSecurityResultItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSecurityResultItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSecurityResultItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABSecurityResultItemExtIEsValue {
			sealed := s04.ERABSecurityResultItemExtIEsValue{}
			*s04.BridgeERABSecurityResultItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABSecurityResultItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABSecurityResultItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABUsageReportItemExtIETable struct{}

func ERABUsageReportItemExtIEs() ERABUsageReportItemExtIETable {
	return ERABUsageReportItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABUsageReportItemExtIETable.
func (ERABUsageReportItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABUsageReportItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABUsageReportItemExtIETable.
func (ERABUsageReportItemExtIETable) Table() s00.ERABUsageReportItemExtIEsValueExtensionTable {
	return func() s00.ERABUsageReportItemExtIEsValueExtensionTable {
		sealed := s00.ERABUsageReportItemExtIEsValueExtensionTable{}
		*s00.BridgeERABUsageReportItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABUsageReportItemExtIETable.
func (t ERABUsageReportItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABUsageReportItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABUsageReportItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABUsageReportItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABUsageReportItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABUsageReportItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABUsageReportItemExtIEsValue {
			sealed := s04.ERABUsageReportItemExtIEsValue{}
			*s04.BridgeERABUsageReportItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABUsageReportItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABUsageReportItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ENDCTransferTypeRequestExtIETable struct{}

func ENDCTransferTypeRequestExtIEs() ENDCTransferTypeRequestExtIETable {
	return ENDCTransferTypeRequestExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENDCTransferTypeRequestExtIETable.
func (ENDCTransferTypeRequestExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EN-DCTransferTypeRequest-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENDCTransferTypeRequestExtIETable.
func (ENDCTransferTypeRequestExtIETable) Table() s00.ENDCTransferTypeRequestExtIEsValueExtensionTable {
	return func() s00.ENDCTransferTypeRequestExtIEsValueExtensionTable {
		sealed := s00.ENDCTransferTypeRequestExtIEsValueExtensionTable{}
		*s00.BridgeENDCTransferTypeRequestExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENDCTransferTypeRequestExtIETable.
func (t ENDCTransferTypeRequestExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENDCTransferTypeRequestExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENDCTransferTypeRequestExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENDCTransferTypeRequestExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENDCTransferTypeRequestExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENDCTransferTypeRequestExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ENDCTransferTypeRequestExtIEsValue {
			sealed := s04.ENDCTransferTypeRequestExtIEsValue{}
			*s04.BridgeENDCTransferTypeRequestExtIEsValueFieldId(&sealed) = id
			*s04.BridgeENDCTransferTypeRequestExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeENDCTransferTypeRequestExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type EUTRANCGIExtIETable struct{}

func EUTRANCGIExtIEs() EUTRANCGIExtIETable { return EUTRANCGIExtIETable{} }

// ID returns the ASN.1 object-set identity of EUTRANCGIExtIETable.
func (EUTRANCGIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by EUTRANCGIExtIETable.
func (EUTRANCGIExtIETable) Table() s00.EUTRANCGIExtIEsValueExtensionTable {
	return func() s00.EUTRANCGIExtIEsValueExtensionTable {
		sealed := s00.EUTRANCGIExtIEsValueExtensionTable{}
		*s00.BridgeEUTRANCGIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in EUTRANCGIExtIETable.
func (t EUTRANCGIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (EUTRANCGIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return EUTRANCGIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return EUTRANCGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return EUTRANCGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return EUTRANCGIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.EUTRANCGIExtIEsValue {
			sealed := s04.EUTRANCGIExtIEsValue{}
			*s04.BridgeEUTRANCGIExtIEsValueFieldId(&sealed) = id
			*s04.BridgeEUTRANCGIExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeEUTRANCGIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type EmergencyAreaIDBroadcastItemExtIETable struct{}

func EmergencyAreaIDBroadcastItemExtIEs() EmergencyAreaIDBroadcastItemExtIETable {
	return EmergencyAreaIDBroadcastItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of EmergencyAreaIDBroadcastItemExtIETable.
func (EmergencyAreaIDBroadcastItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EmergencyAreaID-Broadcast-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by EmergencyAreaIDBroadcastItemExtIETable.
func (EmergencyAreaIDBroadcastItemExtIETable) Table() s00.EmergencyAreaIDBroadcastItemExtIEsValueExtensionTable {
	return func() s00.EmergencyAreaIDBroadcastItemExtIEsValueExtensionTable {
		sealed := s00.EmergencyAreaIDBroadcastItemExtIEsValueExtensionTable{}
		*s00.BridgeEmergencyAreaIDBroadcastItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in EmergencyAreaIDBroadcastItemExtIETable.
func (t EmergencyAreaIDBroadcastItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (EmergencyAreaIDBroadcastItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return EmergencyAreaIDBroadcastItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return EmergencyAreaIDBroadcastItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return EmergencyAreaIDBroadcastItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return EmergencyAreaIDBroadcastItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.EmergencyAreaIDBroadcastItemExtIEsValue {
			sealed := s04.EmergencyAreaIDBroadcastItemExtIEsValue{}
			*s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type EmergencyAreaIDCancelledItemExtIETable struct{}

func EmergencyAreaIDCancelledItemExtIEs() EmergencyAreaIDCancelledItemExtIETable {
	return EmergencyAreaIDCancelledItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of EmergencyAreaIDCancelledItemExtIETable.
func (EmergencyAreaIDCancelledItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EmergencyAreaID-Cancelled-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by EmergencyAreaIDCancelledItemExtIETable.
func (EmergencyAreaIDCancelledItemExtIETable) Table() s00.EmergencyAreaIDCancelledItemExtIEsValueExtensionTable {
	return func() s00.EmergencyAreaIDCancelledItemExtIEsValueExtensionTable {
		sealed := s00.EmergencyAreaIDCancelledItemExtIEsValueExtensionTable{}
		*s00.BridgeEmergencyAreaIDCancelledItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in EmergencyAreaIDCancelledItemExtIETable.
func (t EmergencyAreaIDCancelledItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (EmergencyAreaIDCancelledItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return EmergencyAreaIDCancelledItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return EmergencyAreaIDCancelledItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return EmergencyAreaIDCancelledItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return EmergencyAreaIDCancelledItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.EmergencyAreaIDCancelledItemExtIEsValue {
			sealed := s04.EmergencyAreaIDCancelledItemExtIEsValue{}
			*s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type EventL1LoggedMDTConfigExtIETable struct{}

func EventL1LoggedMDTConfigExtIEs() EventL1LoggedMDTConfigExtIETable {
	return EventL1LoggedMDTConfigExtIETable{}
}

// ID returns the ASN.1 object-set identity of EventL1LoggedMDTConfigExtIETable.
func (EventL1LoggedMDTConfigExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EventL1LoggedMDTConfig-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by EventL1LoggedMDTConfigExtIETable.
func (EventL1LoggedMDTConfigExtIETable) Table() s00.EventL1LoggedMDTConfigExtIEsValueExtensionTable {
	return func() s00.EventL1LoggedMDTConfigExtIEsValueExtensionTable {
		sealed := s00.EventL1LoggedMDTConfigExtIEsValueExtensionTable{}
		*s00.BridgeEventL1LoggedMDTConfigExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in EventL1LoggedMDTConfigExtIETable.
func (t EventL1LoggedMDTConfigExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (EventL1LoggedMDTConfigExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return EventL1LoggedMDTConfigExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return EventL1LoggedMDTConfigExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return EventL1LoggedMDTConfigExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return EventL1LoggedMDTConfigExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.EventL1LoggedMDTConfigExtIEsValue {
			sealed := s04.EventL1LoggedMDTConfigExtIEsValue{}
			*s04.BridgeEventL1LoggedMDTConfigExtIEsValueFieldId(&sealed) = id
			*s04.BridgeEventL1LoggedMDTConfigExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeEventL1LoggedMDTConfigExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type EventTriggerExtIETable struct{}

func EventTriggerExtIEs() EventTriggerExtIETable { return EventTriggerExtIETable{} }

// ID returns the ASN.1 object-set identity of EventTriggerExtIETable.
func (EventTriggerExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EventTrigger-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by EventTriggerExtIETable.
func (EventTriggerExtIETable) Table() s00.EventTriggerExtIEValueIETable {
	return func() s00.EventTriggerExtIEValueIETable {
		sealed := s00.EventTriggerExtIEValueIETable{}
		*s00.BridgeEventTriggerExtIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in EventTriggerExtIETable.
func (t EventTriggerExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (EventTriggerExtIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return EventTriggerExtIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return EventTriggerExtIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return EventTriggerExtIEField{}, aper.OperationError(err, "Opaque")
		}
		return EventTriggerExtIEField{Id: id, Criticality: criticality, Value: func() s04.EventTriggerExtIEValue {
			sealed := s04.EventTriggerExtIEValue{}
			*s04.BridgeEventTriggerExtIEValueFieldId(&sealed) = id
			*s04.BridgeEventTriggerExtIEValueFieldOpaque(&sealed) = opaque
			*s04.BridgeEventTriggerExtIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ExpectedUEActivityBehaviourExtIETable struct{}

func ExpectedUEActivityBehaviourExtIEs() ExpectedUEActivityBehaviourExtIETable {
	return ExpectedUEActivityBehaviourExtIETable{}
}

// ID returns the ASN.1 object-set identity of ExpectedUEActivityBehaviourExtIETable.
func (ExpectedUEActivityBehaviourExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExpectedUEActivityBehaviour-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ExpectedUEActivityBehaviourExtIETable.
func (ExpectedUEActivityBehaviourExtIETable) Table() s00.ExpectedUEActivityBehaviourExtIEsValueExtensionTable {
	return func() s00.ExpectedUEActivityBehaviourExtIEsValueExtensionTable {
		sealed := s00.ExpectedUEActivityBehaviourExtIEsValueExtensionTable{}
		*s00.BridgeExpectedUEActivityBehaviourExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ExpectedUEActivityBehaviourExtIETable.
func (t ExpectedUEActivityBehaviourExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ExpectedUEActivityBehaviourExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ExpectedUEActivityBehaviourExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ExpectedUEActivityBehaviourExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ExpectedUEActivityBehaviourExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ExpectedUEActivityBehaviourExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.ExpectedUEActivityBehaviourExtIEsValue {
			sealed := s05.ExpectedUEActivityBehaviourExtIEsValue{}
			*s05.BridgeExpectedUEActivityBehaviourExtIEsValueFieldId(&sealed) = id
			*s05.BridgeExpectedUEActivityBehaviourExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeExpectedUEActivityBehaviourExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ExpectedUEBehaviourExtIETable struct{}

func ExpectedUEBehaviourExtIEs() ExpectedUEBehaviourExtIETable {
	return ExpectedUEBehaviourExtIETable{}
}

// ID returns the ASN.1 object-set identity of ExpectedUEBehaviourExtIETable.
func (ExpectedUEBehaviourExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExpectedUEBehaviour-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ExpectedUEBehaviourExtIETable.
func (ExpectedUEBehaviourExtIETable) Table() s00.ExpectedUEBehaviourExtIEsValueExtensionTable {
	return func() s00.ExpectedUEBehaviourExtIEsValueExtensionTable {
		sealed := s00.ExpectedUEBehaviourExtIEsValueExtensionTable{}
		*s00.BridgeExpectedUEBehaviourExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ExpectedUEBehaviourExtIETable.
func (t ExpectedUEBehaviourExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ExpectedUEBehaviourExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ExpectedUEBehaviourExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ExpectedUEBehaviourExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ExpectedUEBehaviourExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ExpectedUEBehaviourExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.ExpectedUEBehaviourExtIEsValue {
			sealed := s05.ExpectedUEBehaviourExtIEsValue{}
			*s05.BridgeExpectedUEBehaviourExtIEsValueFieldId(&sealed) = id
			*s05.BridgeExpectedUEBehaviourExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeExpectedUEBehaviourExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type FiveGSTAIExtIETable struct{}

func FiveGSTAIExtIEs() FiveGSTAIExtIETable { return FiveGSTAIExtIETable{} }

// ID returns the ASN.1 object-set identity of FiveGSTAIExtIETable.
func (FiveGSTAIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "FiveGSTAI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by FiveGSTAIExtIETable.
func (FiveGSTAIExtIETable) Table() s00.FiveGSTAIExtIEsValueExtensionTable {
	return func() s00.FiveGSTAIExtIEsValueExtensionTable {
		sealed := s00.FiveGSTAIExtIEsValueExtensionTable{}
		*s00.BridgeFiveGSTAIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in FiveGSTAIExtIETable.
func (t FiveGSTAIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (FiveGSTAIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return FiveGSTAIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return FiveGSTAIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return FiveGSTAIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return FiveGSTAIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.FiveGSTAIExtIEsValue {
			sealed := s05.FiveGSTAIExtIEsValue{}
			*s05.BridgeFiveGSTAIExtIEsValueFieldId(&sealed) = id
			*s05.BridgeFiveGSTAIExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeFiveGSTAIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ForbiddenLAsItemExtIETable struct{}

func ForbiddenLAsItemExtIEs() ForbiddenLAsItemExtIETable { return ForbiddenLAsItemExtIETable{} }

// ID returns the ASN.1 object-set identity of ForbiddenLAsItemExtIETable.
func (ForbiddenLAsItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ForbiddenLAs-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ForbiddenLAsItemExtIETable.
func (ForbiddenLAsItemExtIETable) Table() s00.ForbiddenLAsItemExtIEsValueExtensionTable {
	return func() s00.ForbiddenLAsItemExtIEsValueExtensionTable {
		sealed := s00.ForbiddenLAsItemExtIEsValueExtensionTable{}
		*s00.BridgeForbiddenLAsItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ForbiddenLAsItemExtIETable.
func (t ForbiddenLAsItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ForbiddenLAsItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ForbiddenLAsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ForbiddenLAsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ForbiddenLAsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ForbiddenLAsItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.ForbiddenLAsItemExtIEsValue {
			sealed := s05.ForbiddenLAsItemExtIEsValue{}
			*s05.BridgeForbiddenLAsItemExtIEsValueFieldId(&sealed) = id
			*s05.BridgeForbiddenLAsItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeForbiddenLAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ForbiddenTAsItemExtIETable struct{}

func ForbiddenTAsItemExtIEs() ForbiddenTAsItemExtIETable { return ForbiddenTAsItemExtIETable{} }

// ID returns the ASN.1 object-set identity of ForbiddenTAsItemExtIETable.
func (ForbiddenTAsItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ForbiddenTAs-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ForbiddenTAsItemExtIETable.
func (ForbiddenTAsItemExtIETable) Table() s00.ForbiddenTAsItemExtIEsValueExtensionTable {
	return func() s00.ForbiddenTAsItemExtIEsValueExtensionTable {
		sealed := s00.ForbiddenTAsItemExtIEsValueExtensionTable{}
		*s00.BridgeForbiddenTAsItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ForbiddenTAsItemExtIETable.
func (t ForbiddenTAsItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ForbiddenTAsItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ForbiddenTAsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ForbiddenTAsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ForbiddenTAsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ForbiddenTAsItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.ForbiddenTAsItemExtIEsValue {
			sealed := s05.ForbiddenTAsItemExtIEsValue{}
			*s05.BridgeForbiddenTAsItemExtIEsValueFieldId(&sealed) = id
			*s05.BridgeForbiddenTAsItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeForbiddenTAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABAdmittedItemExtIETable struct{}

func ERABAdmittedItemExtIEs() ERABAdmittedItemExtIETable { return ERABAdmittedItemExtIETable{} }

// ID returns the ASN.1 object-set identity of ERABAdmittedItemExtIETable.
func (ERABAdmittedItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABAdmittedItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABAdmittedItemExtIETable.
func (ERABAdmittedItemExtIETable) Table() s00.ERABAdmittedItemExtIEsValueExtensionTable {
	return func() s00.ERABAdmittedItemExtIEsValueExtensionTable {
		sealed := s00.ERABAdmittedItemExtIEsValueExtensionTable{}
		*s00.BridgeERABAdmittedItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABAdmittedItemExtIETable.
func (t ERABAdmittedItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABAdmittedItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABAdmittedItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABAdmittedItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABAdmittedItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABAdmittedItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABAdmittedItemExtIEsValue {
			sealed := s04.ERABAdmittedItemExtIEsValue{}
			*s04.BridgeERABAdmittedItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABAdmittedItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABAdmittedItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABDataForwardingItemExtIETable struct{}

func ERABDataForwardingItemExtIEs() ERABDataForwardingItemExtIETable {
	return ERABDataForwardingItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABDataForwardingItemExtIETable.
func (ERABDataForwardingItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABDataForwardingItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABDataForwardingItemExtIETable.
func (ERABDataForwardingItemExtIETable) Table() s00.ERABDataForwardingItemExtIEsValueExtensionTable {
	return func() s00.ERABDataForwardingItemExtIEsValueExtensionTable {
		sealed := s00.ERABDataForwardingItemExtIEsValueExtensionTable{}
		*s00.BridgeERABDataForwardingItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABDataForwardingItemExtIETable.
func (t ERABDataForwardingItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABDataForwardingItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABDataForwardingItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABDataForwardingItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABDataForwardingItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABDataForwardingItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABDataForwardingItemExtIEsValue {
			sealed := s04.ERABDataForwardingItemExtIEsValue{}
			*s04.BridgeERABDataForwardingItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABDataForwardingItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABDataForwardingItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABFailedToResumeItemResumeReqExtIETable struct{}

func ERABFailedToResumeItemResumeReqExtIEs() ERABFailedToResumeItemResumeReqExtIETable {
	return ERABFailedToResumeItemResumeReqExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABFailedToResumeItemResumeReqExtIETable.
func (ERABFailedToResumeItemResumeReqExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeItemResumeReq-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABFailedToResumeItemResumeReqExtIETable.
func (ERABFailedToResumeItemResumeReqExtIETable) Table() s00.ERABFailedToResumeItemResumeReqExtIEsValueExtensionTable {
	return func() s00.ERABFailedToResumeItemResumeReqExtIEsValueExtensionTable {
		sealed := s00.ERABFailedToResumeItemResumeReqExtIEsValueExtensionTable{}
		*s00.BridgeERABFailedToResumeItemResumeReqExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABFailedToResumeItemResumeReqExtIETable.
func (t ERABFailedToResumeItemResumeReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABFailedToResumeItemResumeReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABFailedToResumeItemResumeReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABFailedToResumeItemResumeReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABFailedToResumeItemResumeReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABFailedToResumeItemResumeReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABFailedToResumeItemResumeReqExtIEsValue {
			sealed := s04.ERABFailedToResumeItemResumeReqExtIEsValue{}
			*s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABFailedToResumeItemResumeResExtIETable struct{}

func ERABFailedToResumeItemResumeResExtIEs() ERABFailedToResumeItemResumeResExtIETable {
	return ERABFailedToResumeItemResumeResExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABFailedToResumeItemResumeResExtIETable.
func (ERABFailedToResumeItemResumeResExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeItemResumeRes-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABFailedToResumeItemResumeResExtIETable.
func (ERABFailedToResumeItemResumeResExtIETable) Table() s00.ERABFailedToResumeItemResumeResExtIEsValueExtensionTable {
	return func() s00.ERABFailedToResumeItemResumeResExtIEsValueExtensionTable {
		sealed := s00.ERABFailedToResumeItemResumeResExtIEsValueExtensionTable{}
		*s00.BridgeERABFailedToResumeItemResumeResExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABFailedToResumeItemResumeResExtIETable.
func (t ERABFailedToResumeItemResumeResExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABFailedToResumeItemResumeResExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABFailedToResumeItemResumeResExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABFailedToResumeItemResumeResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABFailedToResumeItemResumeResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABFailedToResumeItemResumeResExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABFailedToResumeItemResumeResExtIEsValue {
			sealed := s04.ERABFailedToResumeItemResumeResExtIEsValue{}
			*s04.BridgeERABFailedToResumeItemResumeResExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABFailedToResumeItemResumeResExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABFailedToResumeItemResumeResExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABFailedToSetupItemHOReqAckExtIETable struct{}

func ERABFailedToSetupItemHOReqAckExtIEs() ERABFailedToSetupItemHOReqAckExtIETable {
	return ERABFailedToSetupItemHOReqAckExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABFailedToSetupItemHOReqAckExtIETable.
func (ERABFailedToSetupItemHOReqAckExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToSetupItemHOReqAckExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABFailedToSetupItemHOReqAckExtIETable.
func (ERABFailedToSetupItemHOReqAckExtIETable) Table() s00.ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTable {
	return func() s00.ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTable {
		sealed := s00.ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTable{}
		*s00.BridgeERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABFailedToSetupItemHOReqAckExtIETable.
func (t ERABFailedToSetupItemHOReqAckExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABFailedToSetupItemHOReqAckExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABFailedToSetupItemHOReqAckExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABFailedToSetupItemHOReqAckExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABFailedToSetupItemHOReqAckExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABFailedToSetupItemHOReqAckExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABFailedToSetupItemHOReqAckExtIEsValue {
			sealed := s04.ERABFailedToSetupItemHOReqAckExtIEsValue{}
			*s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModifyItemBearerModConfExtIETable struct{}

func ERABModifyItemBearerModConfExtIEs() ERABModifyItemBearerModConfExtIETable {
	return ERABModifyItemBearerModConfExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABModifyItemBearerModConfExtIETable.
func (ERABModifyItemBearerModConfExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModConfExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModifyItemBearerModConfExtIETable.
func (ERABModifyItemBearerModConfExtIETable) Table() s00.ERABModifyItemBearerModConfExtIEsValueExtensionTable {
	return func() s00.ERABModifyItemBearerModConfExtIEsValueExtensionTable {
		sealed := s00.ERABModifyItemBearerModConfExtIEsValueExtensionTable{}
		*s00.BridgeERABModifyItemBearerModConfExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModifyItemBearerModConfExtIETable.
func (t ERABModifyItemBearerModConfExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABModifyItemBearerModConfExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABModifyItemBearerModConfExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABModifyItemBearerModConfExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABModifyItemBearerModConfExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABModifyItemBearerModConfExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABModifyItemBearerModConfExtIEsValue {
			sealed := s04.ERABModifyItemBearerModConfExtIEsValue{}
			*s04.BridgeERABModifyItemBearerModConfExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABModifyItemBearerModConfExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABModifyItemBearerModConfExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModifyItemBearerModResExtIETable struct{}

func ERABModifyItemBearerModResExtIEs() ERABModifyItemBearerModResExtIETable {
	return ERABModifyItemBearerModResExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABModifyItemBearerModResExtIETable.
func (ERABModifyItemBearerModResExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModResExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModifyItemBearerModResExtIETable.
func (ERABModifyItemBearerModResExtIETable) Table() s00.ERABModifyItemBearerModResExtIEsValueExtensionTable {
	return func() s00.ERABModifyItemBearerModResExtIEsValueExtensionTable {
		sealed := s00.ERABModifyItemBearerModResExtIEsValueExtensionTable{}
		*s00.BridgeERABModifyItemBearerModResExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModifyItemBearerModResExtIETable.
func (t ERABModifyItemBearerModResExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABModifyItemBearerModResExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABModifyItemBearerModResExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABModifyItemBearerModResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABModifyItemBearerModResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABModifyItemBearerModResExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABModifyItemBearerModResExtIEsValue {
			sealed := s04.ERABModifyItemBearerModResExtIEsValue{}
			*s04.BridgeERABModifyItemBearerModResExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABModifyItemBearerModResExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABModifyItemBearerModResExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABNotToBeModifiedItemBearerModIndExtIETable struct{}

func ERABNotToBeModifiedItemBearerModIndExtIEs() ERABNotToBeModifiedItemBearerModIndExtIETable {
	return ERABNotToBeModifiedItemBearerModIndExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABNotToBeModifiedItemBearerModIndExtIETable.
func (ERABNotToBeModifiedItemBearerModIndExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABNotToBeModifiedItemBearerModInd-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABNotToBeModifiedItemBearerModIndExtIETable.
func (ERABNotToBeModifiedItemBearerModIndExtIETable) Table() s00.ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTable {
	return func() s00.ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTable {
		sealed := s00.ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTable{}
		*s00.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABNotToBeModifiedItemBearerModIndExtIETable.
func (t ERABNotToBeModifiedItemBearerModIndExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABNotToBeModifiedItemBearerModIndExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABNotToBeModifiedItemBearerModIndExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue {
			sealed := s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue{}
			*s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABReleaseItemBearerRelCompExtIETable struct{}

func ERABReleaseItemBearerRelCompExtIEs() ERABReleaseItemBearerRelCompExtIETable {
	return ERABReleaseItemBearerRelCompExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABReleaseItemBearerRelCompExtIETable.
func (ERABReleaseItemBearerRelCompExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseItemBearerRelCompExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABReleaseItemBearerRelCompExtIETable.
func (ERABReleaseItemBearerRelCompExtIETable) Table() s00.ERABReleaseItemBearerRelCompExtIEsValueExtensionTable {
	return func() s00.ERABReleaseItemBearerRelCompExtIEsValueExtensionTable {
		sealed := s00.ERABReleaseItemBearerRelCompExtIEsValueExtensionTable{}
		*s00.BridgeERABReleaseItemBearerRelCompExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABReleaseItemBearerRelCompExtIETable.
func (t ERABReleaseItemBearerRelCompExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABReleaseItemBearerRelCompExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABReleaseItemBearerRelCompExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABReleaseItemBearerRelCompExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABReleaseItemBearerRelCompExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABReleaseItemBearerRelCompExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABReleaseItemBearerRelCompExtIEsValue {
			sealed := s04.ERABReleaseItemBearerRelCompExtIEsValue{}
			*s04.BridgeERABReleaseItemBearerRelCompExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABReleaseItemBearerRelCompExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABReleaseItemBearerRelCompExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupItemBearerSUResExtIETable struct{}

func ERABSetupItemBearerSUResExtIEs() ERABSetupItemBearerSUResExtIETable {
	return ERABSetupItemBearerSUResExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABSetupItemBearerSUResExtIETable.
func (ERABSetupItemBearerSUResExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemBearerSUResExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSetupItemBearerSUResExtIETable.
func (ERABSetupItemBearerSUResExtIETable) Table() s00.ERABSetupItemBearerSUResExtIEsValueExtensionTable {
	return func() s00.ERABSetupItemBearerSUResExtIEsValueExtensionTable {
		sealed := s00.ERABSetupItemBearerSUResExtIEsValueExtensionTable{}
		*s00.BridgeERABSetupItemBearerSUResExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSetupItemBearerSUResExtIETable.
func (t ERABSetupItemBearerSUResExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABSetupItemBearerSUResExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSetupItemBearerSUResExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSetupItemBearerSUResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSetupItemBearerSUResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSetupItemBearerSUResExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABSetupItemBearerSUResExtIEsValue {
			sealed := s04.ERABSetupItemBearerSUResExtIEsValue{}
			*s04.BridgeERABSetupItemBearerSUResExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABSetupItemBearerSUResExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABSetupItemBearerSUResExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupItemCtxtSUResExtIETable struct{}

func ERABSetupItemCtxtSUResExtIEs() ERABSetupItemCtxtSUResExtIETable {
	return ERABSetupItemCtxtSUResExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABSetupItemCtxtSUResExtIETable.
func (ERABSetupItemCtxtSUResExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemCtxtSUResExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSetupItemCtxtSUResExtIETable.
func (ERABSetupItemCtxtSUResExtIETable) Table() s00.ERABSetupItemCtxtSUResExtIEsValueExtensionTable {
	return func() s00.ERABSetupItemCtxtSUResExtIEsValueExtensionTable {
		sealed := s00.ERABSetupItemCtxtSUResExtIEsValueExtensionTable{}
		*s00.BridgeERABSetupItemCtxtSUResExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSetupItemCtxtSUResExtIETable.
func (t ERABSetupItemCtxtSUResExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABSetupItemCtxtSUResExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSetupItemCtxtSUResExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSetupItemCtxtSUResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSetupItemCtxtSUResExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSetupItemCtxtSUResExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABSetupItemCtxtSUResExtIEsValue {
			sealed := s04.ERABSetupItemCtxtSUResExtIEsValue{}
			*s04.BridgeERABSetupItemCtxtSUResExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABSetupItemCtxtSUResExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABSetupItemCtxtSUResExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeModifiedItemBearerModIndExtIETable struct{}

func ERABToBeModifiedItemBearerModIndExtIEs() ERABToBeModifiedItemBearerModIndExtIETable {
	return ERABToBeModifiedItemBearerModIndExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeModifiedItemBearerModIndExtIETable.
func (ERABToBeModifiedItemBearerModIndExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModInd-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeModifiedItemBearerModIndExtIETable.
func (ERABToBeModifiedItemBearerModIndExtIETable) Table() s00.ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTable {
	return func() s00.ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTable {
		sealed := s00.ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeModifiedItemBearerModIndExtIETable.
func (t ERABToBeModifiedItemBearerModIndExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeModifiedItemBearerModIndExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeModifiedItemBearerModIndExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeModifiedItemBearerModIndExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeModifiedItemBearerModIndExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABToBeModifiedItemBearerModIndExtIEsValue {
			sealed := s04.ERABToBeModifiedItemBearerModIndExtIEsValue{}
			*s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSwitchedULItemExtIETable struct{}

func ERABToBeSwitchedULItemExtIEs() ERABToBeSwitchedULItemExtIETable {
	return ERABToBeSwitchedULItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSwitchedULItemExtIETable.
func (ERABToBeSwitchedULItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSwitchedULItemExtIETable.
func (ERABToBeSwitchedULItemExtIETable) Table() s00.ERABToBeSwitchedULItemExtIEsValueExtensionTable {
	return func() s00.ERABToBeSwitchedULItemExtIEsValueExtensionTable {
		sealed := s00.ERABToBeSwitchedULItemExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeSwitchedULItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSwitchedULItemExtIETable.
func (t ERABToBeSwitchedULItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeSwitchedULItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSwitchedULItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSwitchedULItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSwitchedULItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSwitchedULItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABToBeSwitchedULItemExtIEsValue {
			sealed := s04.ERABToBeSwitchedULItemExtIEsValue{}
			*s04.BridgeERABToBeSwitchedULItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABToBeSwitchedULItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABToBeSwitchedULItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeUpdatedItemExtIETable struct{}

func ERABToBeUpdatedItemExtIEs() ERABToBeUpdatedItemExtIETable {
	return ERABToBeUpdatedItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeUpdatedItemExtIETable.
func (ERABToBeUpdatedItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeUpdatedItemExtIETable.
func (ERABToBeUpdatedItemExtIETable) Table() s00.ERABToBeUpdatedItemExtIEsValueExtensionTable {
	return func() s00.ERABToBeUpdatedItemExtIEsValueExtensionTable {
		sealed := s00.ERABToBeUpdatedItemExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeUpdatedItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeUpdatedItemExtIETable.
func (t ERABToBeUpdatedItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeUpdatedItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeUpdatedItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeUpdatedItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeUpdatedItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeUpdatedItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ERABToBeUpdatedItemExtIEsValue {
			sealed := s04.ERABToBeUpdatedItemExtIEsValue{}
			*s04.BridgeERABToBeUpdatedItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeERABToBeUpdatedItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeERABToBeUpdatedItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// ExtendedRNCIDCodec binds the complete source value type.
func ExtendedRNCIDCodec() s00.ExtendedRNCIDValueCodec {
	return func() s00.ExtendedRNCIDValueCodec {
		sealed := s00.ExtendedRNCIDValueCodec{}
		*s00.BridgeExtendedRNCIDValueCodecFieldPath(&sealed) = "ExtendedRNCID"
		*s00.BridgeExtendedRNCIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedRNCID, error) {
			var zero s00.ExtendedRNCID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ExtendedRNCID, error) {
				var v struct{ Value s00.ExtendedRNCID }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(4096), s08.BridgeInt64Ptr(65535), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ExtendedRNCID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ExtendedRNCID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeExtendedRNCIDValueCodecFieldEncode(&sealed) = func(value s00.ExtendedRNCID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ExtendedRNCID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ExtendedRNCID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(4096), s08.BridgeInt64Ptr(65535), false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeExtendedRNCIDValueCodecFieldCapture(&sealed) = func(v s00.ExtendedRNCID, options aper.DecodeState) (s00.ExtendedRNCID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedRNCID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeExtendedRNCIDValueCodecFieldCompare(&sealed) = func(v s00.ExtendedRNCID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APExtendedRNCID(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeExtendedRNCIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedRNCID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldCapture(v *ENDCTransferTypeRequestExtIEsExtContainerValueCodec) *func(ENDCTransferTypeRequestExtIEsExtContainer, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldCompare(v *ENDCTransferTypeRequestExtIEsExtContainerValueCodec) *func(ENDCTransferTypeRequestExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldContext(v *ENDCTransferTypeRequestExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldDecode(v *ENDCTransferTypeRequestExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldEncode(v *ENDCTransferTypeRequestExtIEsExtContainerValueCodec) *func(ENDCTransferTypeRequestExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldPath(v *ENDCTransferTypeRequestExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldFieldReplay(v *ENDCTransferTypeRequestExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldFieldWithoutReplay(v *ENDCTransferTypeRequestExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldMethodMarshalAPERTo(v *ENDCTransferTypeRequestExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENDCTransferTypeRequestExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldCapture(v *ENDCTransferTypeRequestExtIEsExtFieldValueCodec) *func(ENDCTransferTypeRequestExtIEsExtField, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldCompare(v *ENDCTransferTypeRequestExtIEsExtFieldValueCodec) *func(ENDCTransferTypeRequestExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldContext(v *ENDCTransferTypeRequestExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldDecode(v *ENDCTransferTypeRequestExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENDCTransferTypeRequestExtIEsExtField, error) {
	return &v.decode
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldEncode(v *ENDCTransferTypeRequestExtIEsExtFieldValueCodec) *func(ENDCTransferTypeRequestExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldPath(v *ENDCTransferTypeRequestExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldCapture(v *ERABAdmittedItemExtIEsExtContainerValueCodec) *func(ERABAdmittedItemExtIEsExtContainer, aper.DecodeState) (ERABAdmittedItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldCompare(v *ERABAdmittedItemExtIEsExtContainerValueCodec) *func(ERABAdmittedItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldContext(v *ERABAdmittedItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldDecode(v *ERABAdmittedItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldEncode(v *ERABAdmittedItemExtIEsExtContainerValueCodec) *func(ERABAdmittedItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldPath(v *ERABAdmittedItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemExtIEsExtFieldFieldReplay(v *ERABAdmittedItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemExtIEsExtFieldFieldWithoutReplay(v *ERABAdmittedItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABAdmittedItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABAdmittedItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABAdmittedItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldCapture(v *ERABAdmittedItemExtIEsExtFieldValueCodec) *func(ERABAdmittedItemExtIEsExtField, aper.DecodeState) (ERABAdmittedItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldCompare(v *ERABAdmittedItemExtIEsExtFieldValueCodec) *func(ERABAdmittedItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldContext(v *ERABAdmittedItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldDecode(v *ERABAdmittedItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldEncode(v *ERABAdmittedItemExtIEsExtFieldValueCodec) *func(ERABAdmittedItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldPath(v *ERABAdmittedItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldCapture(v *ERABDataForwardingItemExtIEsExtContainerValueCodec) *func(ERABDataForwardingItemExtIEsExtContainer, aper.DecodeState) (ERABDataForwardingItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldCompare(v *ERABDataForwardingItemExtIEsExtContainerValueCodec) *func(ERABDataForwardingItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldContext(v *ERABDataForwardingItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldDecode(v *ERABDataForwardingItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldEncode(v *ERABDataForwardingItemExtIEsExtContainerValueCodec) *func(ERABDataForwardingItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldPath(v *ERABDataForwardingItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemExtIEsExtFieldFieldReplay(v *ERABDataForwardingItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemExtIEsExtFieldFieldWithoutReplay(v *ERABDataForwardingItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABDataForwardingItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABDataForwardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABDataForwardingItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldCapture(v *ERABDataForwardingItemExtIEsExtFieldValueCodec) *func(ERABDataForwardingItemExtIEsExtField, aper.DecodeState) (ERABDataForwardingItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldCompare(v *ERABDataForwardingItemExtIEsExtFieldValueCodec) *func(ERABDataForwardingItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldContext(v *ERABDataForwardingItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldDecode(v *ERABDataForwardingItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldEncode(v *ERABDataForwardingItemExtIEsExtFieldValueCodec) *func(ERABDataForwardingItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldPath(v *ERABDataForwardingItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) *func(ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) *func(ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) *func(ERABFailedToResumeItemResumeReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldReplay(v *ERABFailedToResumeItemResumeReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodMarshalAPERTo(v *ERABFailedToResumeItemResumeReqExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABFailedToResumeItemResumeReqExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) *func(ERABFailedToResumeItemResumeReqExtIEsExtField, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) *func(ERABFailedToResumeItemResumeReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) *func(ERABFailedToResumeItemResumeReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldCapture(v *ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) *func(ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldCompare(v *ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) *func(ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldContext(v *ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldDecode(v *ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldEncode(v *ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) *func(ERABFailedToResumeItemResumeResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldPath(v *ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldReplay(v *ERABFailedToResumeItemResumeResExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldWithoutReplay(v *ERABFailedToResumeItemResumeResExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodMarshalAPERTo(v *ERABFailedToResumeItemResumeResExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABFailedToResumeItemResumeResExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldCapture(v *ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) *func(ERABFailedToResumeItemResumeResExtIEsExtField, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldCompare(v *ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) *func(ERABFailedToResumeItemResumeResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldContext(v *ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldDecode(v *ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeResExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldEncode(v *ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) *func(ERABFailedToResumeItemResumeResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldPath(v *ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldCapture(v *ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) *func(ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldCompare(v *ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) *func(ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldContext(v *ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldDecode(v *ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldEncode(v *ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) *func(ERABFailedToSetupItemHOReqAckExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldPath(v *ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldReplay(v *ERABFailedToSetupItemHOReqAckExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldWithoutReplay(v *ERABFailedToSetupItemHOReqAckExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodMarshalAPERTo(v *ERABFailedToSetupItemHOReqAckExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABFailedToSetupItemHOReqAckExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldCapture(v *ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) *func(ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldCompare(v *ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) *func(ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldContext(v *ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldDecode(v *ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToSetupItemHOReqAckExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldEncode(v *ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) *func(ERABFailedToSetupItemHOReqAckExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldPath(v *ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABItemExtIEsExtContainerValueCodecFieldCapture(v *ERABItemExtIEsExtContainerValueCodec) *func(ERABItemExtIEsExtContainer, aper.DecodeState) (ERABItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemExtIEsExtContainerValueCodecFieldCompare(v *ERABItemExtIEsExtContainerValueCodec) *func(ERABItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemExtIEsExtContainerValueCodecFieldContext(v *ERABItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemExtIEsExtContainerValueCodecFieldDecode(v *ERABItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABItemExtIEsExtContainerValueCodecFieldEncode(v *ERABItemExtIEsExtContainerValueCodec) *func(ERABItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemExtIEsExtContainerValueCodecFieldPath(v *ERABItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABItemExtIEsExtFieldFieldReplay(v *ERABItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABItemExtIEsExtFieldFieldWithoutReplay(v *ERABItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABItemExtIEsExtFieldValueCodecFieldCapture(v *ERABItemExtIEsExtFieldValueCodec) *func(ERABItemExtIEsExtField, aper.DecodeState) (ERABItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemExtIEsExtFieldValueCodecFieldCompare(v *ERABItemExtIEsExtFieldValueCodec) *func(ERABItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemExtIEsExtFieldValueCodecFieldContext(v *ERABItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemExtIEsExtFieldValueCodecFieldDecode(v *ERABItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABItemExtIEsExtFieldValueCodecFieldEncode(v *ERABItemExtIEsExtFieldValueCodec) *func(ERABItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemExtIEsExtFieldValueCodecFieldPath(v *ERABItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldCapture(v *ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) *func(ERABModifyItemBearerModConfExtIEsExtContainer, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldCompare(v *ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) *func(ERABModifyItemBearerModConfExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldContext(v *ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldDecode(v *ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldEncode(v *ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) *func(ERABModifyItemBearerModConfExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldPath(v *ERABModifyItemBearerModConfExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldReplay(v *ERABModifyItemBearerModConfExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldWithoutReplay(v *ERABModifyItemBearerModConfExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodMarshalAPERTo(v *ERABModifyItemBearerModConfExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABModifyItemBearerModConfExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldCapture(v *ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) *func(ERABModifyItemBearerModConfExtIEsExtField, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldCompare(v *ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) *func(ERABModifyItemBearerModConfExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldContext(v *ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldDecode(v *ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldEncode(v *ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) *func(ERABModifyItemBearerModConfExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldPath(v *ERABModifyItemBearerModConfExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldCapture(v *ERABModifyItemBearerModResExtIEsExtContainerValueCodec) *func(ERABModifyItemBearerModResExtIEsExtContainer, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldCompare(v *ERABModifyItemBearerModResExtIEsExtContainerValueCodec) *func(ERABModifyItemBearerModResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldContext(v *ERABModifyItemBearerModResExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldDecode(v *ERABModifyItemBearerModResExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldEncode(v *ERABModifyItemBearerModResExtIEsExtContainerValueCodec) *func(ERABModifyItemBearerModResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldPath(v *ERABModifyItemBearerModResExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldFieldReplay(v *ERABModifyItemBearerModResExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldFieldWithoutReplay(v *ERABModifyItemBearerModResExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldMethodMarshalAPERTo(v *ERABModifyItemBearerModResExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABModifyItemBearerModResExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldCapture(v *ERABModifyItemBearerModResExtIEsExtFieldValueCodec) *func(ERABModifyItemBearerModResExtIEsExtField, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldCompare(v *ERABModifyItemBearerModResExtIEsExtFieldValueCodec) *func(ERABModifyItemBearerModResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldContext(v *ERABModifyItemBearerModResExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldDecode(v *ERABModifyItemBearerModResExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModResExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldEncode(v *ERABModifyItemBearerModResExtIEsExtFieldValueCodec) *func(ERABModifyItemBearerModResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldPath(v *ERABModifyItemBearerModResExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func(ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func(ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func(ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func(ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func(ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func(ERABNotToBeModifiedItemBearerModIndExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldCapture(v *ERABQoSParametersExtIEsExtContainerValueCodec) *func(ERABQoSParametersExtIEsExtContainer, aper.DecodeState) (ERABQoSParametersExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldCompare(v *ERABQoSParametersExtIEsExtContainerValueCodec) *func(ERABQoSParametersExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldContext(v *ERABQoSParametersExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldDecode(v *ERABQoSParametersExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABQoSParametersExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldEncode(v *ERABQoSParametersExtIEsExtContainerValueCodec) *func(ERABQoSParametersExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldPath(v *ERABQoSParametersExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABQoSParametersExtIEsExtFieldFieldReplay(v *ERABQoSParametersExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABQoSParametersExtIEsExtFieldFieldWithoutReplay(v *ERABQoSParametersExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABQoSParametersExtIEsExtFieldMethodMarshalAPERTo(v *ERABQoSParametersExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABQoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABQoSParametersExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldCapture(v *ERABQoSParametersExtIEsExtFieldValueCodec) *func(ERABQoSParametersExtIEsExtField, aper.DecodeState) (ERABQoSParametersExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldCompare(v *ERABQoSParametersExtIEsExtFieldValueCodec) *func(ERABQoSParametersExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldContext(v *ERABQoSParametersExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldDecode(v *ERABQoSParametersExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABQoSParametersExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldEncode(v *ERABQoSParametersExtIEsExtFieldValueCodec) *func(ERABQoSParametersExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldPath(v *ERABQoSParametersExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABQoSParametersExtIEsValueFieldId(v *ERABQoSParametersExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABQoSParametersExtIEsValueFieldIsOpaque(v *ERABQoSParametersExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABQoSParametersExtIEsValueFieldOpaque(v *ERABQoSParametersExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABQoSParametersExtIEsValueFieldRowDownlinkPacketLossRate(v *ERABQoSParametersExtIEsValue) **s00.PacketLossRate {
	return &v.rowDownlinkPacketLossRate
}
func BridgeERABQoSParametersExtIEsValueFieldRowUplinkPacketLossRate(v *ERABQoSParametersExtIEsValue) **s00.PacketLossRate {
	return &v.rowUplinkPacketLossRate
}
func BridgeERABQoSParametersExtIEsValueMethodCaptureSemantics(v ERABQoSParametersExtIEsValue, a0 aper.SemanticCapture) ERABQoSParametersExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABQoSParametersExtIEsValueMethodCompareSemantics(v ERABQoSParametersExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABQoSParametersExtIEsValueMethodMatchesID(v ERABQoSParametersExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABQoSParametersExtIEsValueMethodRule(v ERABQoSParametersExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) *func(ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) *func(ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldContext(v *ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) *func(ERABReleaseItemBearerRelCompExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldPath(v *ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldReplay(v *ERABReleaseItemBearerRelCompExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldWithoutReplay(v *ERABReleaseItemBearerRelCompExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodMarshalAPERTo(v *ERABReleaseItemBearerRelCompExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABReleaseItemBearerRelCompExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) *func(ERABReleaseItemBearerRelCompExtIEsExtField, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) *func(ERABReleaseItemBearerRelCompExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldContext(v *ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) *func(ERABReleaseItemBearerRelCompExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldPath(v *ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldCapture(v *ERABSecurityResultItemExtIEsExtContainerValueCodec) *func(ERABSecurityResultItemExtIEsExtContainer, aper.DecodeState) (ERABSecurityResultItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldCompare(v *ERABSecurityResultItemExtIEsExtContainerValueCodec) *func(ERABSecurityResultItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldContext(v *ERABSecurityResultItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldDecode(v *ERABSecurityResultItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldEncode(v *ERABSecurityResultItemExtIEsExtContainerValueCodec) *func(ERABSecurityResultItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldPath(v *ERABSecurityResultItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSecurityResultItemExtIEsExtFieldFieldReplay(v *ERABSecurityResultItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultItemExtIEsExtFieldFieldWithoutReplay(v *ERABSecurityResultItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABSecurityResultItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSecurityResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABSecurityResultItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldCapture(v *ERABSecurityResultItemExtIEsExtFieldValueCodec) *func(ERABSecurityResultItemExtIEsExtField, aper.DecodeState) (ERABSecurityResultItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldCompare(v *ERABSecurityResultItemExtIEsExtFieldValueCodec) *func(ERABSecurityResultItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldContext(v *ERABSecurityResultItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldDecode(v *ERABSecurityResultItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSecurityResultItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldEncode(v *ERABSecurityResultItemExtIEsExtFieldValueCodec) *func(ERABSecurityResultItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldPath(v *ERABSecurityResultItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldCapture(v *ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) *func(ERABSetupItemBearerSUResExtIEsExtContainer, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldCompare(v *ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) *func(ERABSetupItemBearerSUResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldContext(v *ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldDecode(v *ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldEncode(v *ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) *func(ERABSetupItemBearerSUResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldPath(v *ERABSetupItemBearerSUResExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldReplay(v *ERABSetupItemBearerSUResExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldWithoutReplay(v *ERABSetupItemBearerSUResExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodMarshalAPERTo(v *ERABSetupItemBearerSUResExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABSetupItemBearerSUResExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldCapture(v *ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) *func(ERABSetupItemBearerSUResExtIEsExtField, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldCompare(v *ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) *func(ERABSetupItemBearerSUResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldContext(v *ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldDecode(v *ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldEncode(v *ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) *func(ERABSetupItemBearerSUResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldPath(v *ERABSetupItemBearerSUResExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldCapture(v *ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) *func(ERABSetupItemCtxtSUResExtIEsExtContainer, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldCompare(v *ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) *func(ERABSetupItemCtxtSUResExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldContext(v *ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldDecode(v *ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldEncode(v *ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) *func(ERABSetupItemCtxtSUResExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldPath(v *ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldReplay(v *ERABSetupItemCtxtSUResExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldWithoutReplay(v *ERABSetupItemCtxtSUResExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodMarshalAPERTo(v *ERABSetupItemCtxtSUResExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABSetupItemCtxtSUResExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldCapture(v *ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) *func(ERABSetupItemCtxtSUResExtIEsExtField, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldCompare(v *ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) *func(ERABSetupItemCtxtSUResExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldContext(v *ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldDecode(v *ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldEncode(v *ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) *func(ERABSetupItemCtxtSUResExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldPath(v *ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func(ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func(ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldContext(v *ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *func(ERABToBeModifiedItemBearerModIndExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldPath(v *ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v *ERABToBeModifiedItemBearerModIndExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v *ERABToBeModifiedItemBearerModIndExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeModifiedItemBearerModIndExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeModifiedItemBearerModIndExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func(ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func(ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldContext(v *ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *func(ERABToBeModifiedItemBearerModIndExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldPath(v *ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) *func(ERABToBeSwitchedULItemExtIEsExtContainer, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) *func(ERABToBeSwitchedULItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldContext(v *ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) *func(ERABToBeSwitchedULItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldPath(v *ERABToBeSwitchedULItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldReplay(v *ERABToBeSwitchedULItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldWithoutReplay(v *ERABToBeSwitchedULItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeSwitchedULItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeSwitchedULItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) *func(ERABToBeSwitchedULItemExtIEsExtField, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) *func(ERABToBeSwitchedULItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldContext(v *ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) *func(ERABToBeSwitchedULItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldPath(v *ERABToBeSwitchedULItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeUpdatedItemExtIEsExtContainerValueCodec) *func(ERABToBeUpdatedItemExtIEsExtContainer, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeUpdatedItemExtIEsExtContainerValueCodec) *func(ERABToBeUpdatedItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldContext(v *ERABToBeUpdatedItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeUpdatedItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeUpdatedItemExtIEsExtContainerValueCodec) *func(ERABToBeUpdatedItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldPath(v *ERABToBeUpdatedItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldFieldReplay(v *ERABToBeUpdatedItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldFieldWithoutReplay(v *ERABToBeUpdatedItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeUpdatedItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeUpdatedItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeUpdatedItemExtIEsExtFieldValueCodec) *func(ERABToBeUpdatedItemExtIEsExtField, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeUpdatedItemExtIEsExtFieldValueCodec) *func(ERABToBeUpdatedItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldContext(v *ERABToBeUpdatedItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeUpdatedItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeUpdatedItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeUpdatedItemExtIEsExtFieldValueCodec) *func(ERABToBeUpdatedItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldPath(v *ERABToBeUpdatedItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldCapture(v *ERABUsageReportItemExtIEsExtContainerValueCodec) *func(ERABUsageReportItemExtIEsExtContainer, aper.DecodeState) (ERABUsageReportItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldCompare(v *ERABUsageReportItemExtIEsExtContainerValueCodec) *func(ERABUsageReportItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldContext(v *ERABUsageReportItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldDecode(v *ERABUsageReportItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldEncode(v *ERABUsageReportItemExtIEsExtContainerValueCodec) *func(ERABUsageReportItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldPath(v *ERABUsageReportItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportItemExtIEsExtFieldFieldReplay(v *ERABUsageReportItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABUsageReportItemExtIEsExtFieldFieldWithoutReplay(v *ERABUsageReportItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABUsageReportItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABUsageReportItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldCapture(v *ERABUsageReportItemExtIEsExtFieldValueCodec) *func(ERABUsageReportItemExtIEsExtField, aper.DecodeState) (ERABUsageReportItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldCompare(v *ERABUsageReportItemExtIEsExtFieldValueCodec) *func(ERABUsageReportItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldContext(v *ERABUsageReportItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldDecode(v *ERABUsageReportItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldEncode(v *ERABUsageReportItemExtIEsExtFieldValueCodec) *func(ERABUsageReportItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldPath(v *ERABUsageReportItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldCapture(v *EUTRANCGIExtIEsExtContainerValueCodec) *func(EUTRANCGIExtIEsExtContainer, aper.DecodeState) (EUTRANCGIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldCompare(v *EUTRANCGIExtIEsExtContainerValueCodec) *func(EUTRANCGIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldContext(v *EUTRANCGIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldDecode(v *EUTRANCGIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (EUTRANCGIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldEncode(v *EUTRANCGIExtIEsExtContainerValueCodec) *func(EUTRANCGIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldPath(v *EUTRANCGIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeEUTRANCGIExtIEsExtFieldFieldReplay(v *EUTRANCGIExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeEUTRANCGIExtIEsExtFieldFieldWithoutReplay(v *EUTRANCGIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeEUTRANCGIExtIEsExtFieldMethodMarshalAPERTo(v *EUTRANCGIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEUTRANCGIExtIEsExtFieldMethodUnmarshalAPERFrom(v *EUTRANCGIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldCapture(v *EUTRANCGIExtIEsExtFieldValueCodec) *func(EUTRANCGIExtIEsExtField, aper.DecodeState) (EUTRANCGIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldCompare(v *EUTRANCGIExtIEsExtFieldValueCodec) *func(EUTRANCGIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldContext(v *EUTRANCGIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldDecode(v *EUTRANCGIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (EUTRANCGIExtIEsExtField, error) {
	return &v.decode
}
func BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldEncode(v *EUTRANCGIExtIEsExtFieldValueCodec) *func(EUTRANCGIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldPath(v *EUTRANCGIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldCapture(v *EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) *func(EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldCompare(v *EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) *func(EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldContext(v *EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldDecode(v *EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldEncode(v *EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) *func(EmergencyAreaIDBroadcastItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldPath(v *EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldReplay(v *EmergencyAreaIDBroadcastItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v *EmergencyAreaIDBroadcastItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(v *EmergencyAreaIDBroadcastItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *EmergencyAreaIDBroadcastItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldCapture(v *EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) *func(EmergencyAreaIDBroadcastItemExtIEsExtField, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldCompare(v *EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) *func(EmergencyAreaIDBroadcastItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldContext(v *EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldDecode(v *EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcastItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldEncode(v *EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) *func(EmergencyAreaIDBroadcastItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldPath(v *EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldCapture(v *EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) *func(EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldCompare(v *EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) *func(EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldContext(v *EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldDecode(v *EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldEncode(v *EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) *func(EmergencyAreaIDCancelledItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldPath(v *EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldReplay(v *EmergencyAreaIDCancelledItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v *EmergencyAreaIDCancelledItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(v *EmergencyAreaIDCancelledItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *EmergencyAreaIDCancelledItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldCapture(v *EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) *func(EmergencyAreaIDCancelledItemExtIEsExtField, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldCompare(v *EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) *func(EmergencyAreaIDCancelledItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldContext(v *EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldDecode(v *EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDCancelledItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldEncode(v *EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) *func(EmergencyAreaIDCancelledItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldPath(v *EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldCapture(v *EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) *func(EventL1LoggedMDTConfigExtIEsExtContainer, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldCompare(v *EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) *func(EventL1LoggedMDTConfigExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldContext(v *EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldDecode(v *EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldEncode(v *EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) *func(EventL1LoggedMDTConfigExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldPath(v *EventL1LoggedMDTConfigExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldReplay(v *EventL1LoggedMDTConfigExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldWithoutReplay(v *EventL1LoggedMDTConfigExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodMarshalAPERTo(v *EventL1LoggedMDTConfigExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodUnmarshalAPERFrom(v *EventL1LoggedMDTConfigExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldCapture(v *EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) *func(EventL1LoggedMDTConfigExtIEsExtField, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldCompare(v *EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) *func(EventL1LoggedMDTConfigExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldContext(v *EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldDecode(v *EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (EventL1LoggedMDTConfigExtIEsExtField, error) {
	return &v.decode
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldEncode(v *EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) *func(EventL1LoggedMDTConfigExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldPath(v *EventL1LoggedMDTConfigExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventTriggerExtIEContainerValueCodecFieldCapture(v *EventTriggerExtIEContainerValueCodec) *func(EventTriggerExtIEContainer, aper.DecodeState) (EventTriggerExtIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggerExtIEContainerValueCodecFieldCompare(v *EventTriggerExtIEContainerValueCodec) *func(EventTriggerExtIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggerExtIEContainerValueCodecFieldContext(v *EventTriggerExtIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggerExtIEContainerValueCodecFieldDecode(v *EventTriggerExtIEContainerValueCodec) *func([]byte, aper.DecodeState) (EventTriggerExtIEContainer, error) {
	return &v.decode
}
func BridgeEventTriggerExtIEContainerValueCodecFieldEncode(v *EventTriggerExtIEContainerValueCodec) *func(EventTriggerExtIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggerExtIEContainerValueCodecFieldPath(v *EventTriggerExtIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventTriggerExtIEFieldFieldReplay(v *EventTriggerExtIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeEventTriggerExtIEFieldFieldWithoutReplay(v *EventTriggerExtIEField) *bool {
	return &v.withoutReplay
}
func BridgeEventTriggerExtIEFieldMethodMarshalAPERTo(v *EventTriggerExtIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(v *EventTriggerExtIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEventTriggerExtIEFieldValueCodecFieldCapture(v *EventTriggerExtIEFieldValueCodec) *func(EventTriggerExtIEField, aper.DecodeState) (EventTriggerExtIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggerExtIEFieldValueCodecFieldCompare(v *EventTriggerExtIEFieldValueCodec) *func(EventTriggerExtIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggerExtIEFieldValueCodecFieldContext(v *EventTriggerExtIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggerExtIEFieldValueCodecFieldDecode(v *EventTriggerExtIEFieldValueCodec) *func([]byte, aper.DecodeState) (EventTriggerExtIEField, error) {
	return &v.decode
}
func BridgeEventTriggerExtIEFieldValueCodecFieldEncode(v *EventTriggerExtIEFieldValueCodec) *func(EventTriggerExtIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggerExtIEFieldValueCodecFieldPath(v *EventTriggerExtIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldCapture(v *EventTriggerExtIEValueERABIEContainerListValueCodec) *func(EventTriggerExtIEValueERABIEContainerList, aper.DecodeState) (EventTriggerExtIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldCompare(v *EventTriggerExtIEValueERABIEContainerListValueCodec) *func(EventTriggerExtIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldContext(v *EventTriggerExtIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldDecode(v *EventTriggerExtIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (EventTriggerExtIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldEncode(v *EventTriggerExtIEValueERABIEContainerListValueCodec) *func(EventTriggerExtIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldPath(v *EventTriggerExtIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) *func(EventTriggerExtIEValueProtocolErrorIEContainerList, aper.DecodeState) (EventTriggerExtIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) *func(EventTriggerExtIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (EventTriggerExtIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) *func(EventTriggerExtIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldCapture(v *EventTriggerExtIEValueProtocolIEContainerListValueCodec) *func(EventTriggerExtIEValueProtocolIEContainerList, aper.DecodeState) (EventTriggerExtIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldCompare(v *EventTriggerExtIEValueProtocolIEContainerListValueCodec) *func(EventTriggerExtIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldContext(v *EventTriggerExtIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldDecode(v *EventTriggerExtIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (EventTriggerExtIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldEncode(v *EventTriggerExtIEValueProtocolIEContainerListValueCodec) *func(EventTriggerExtIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldPath(v *EventTriggerExtIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldCapture(v *ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) *func(ExpectedUEActivityBehaviourExtIEsExtContainer, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldCompare(v *ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) *func(ExpectedUEActivityBehaviourExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldContext(v *ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldDecode(v *ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldEncode(v *ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) *func(ExpectedUEActivityBehaviourExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldPath(v *ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldReplay(v *ExpectedUEActivityBehaviourExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldWithoutReplay(v *ExpectedUEActivityBehaviourExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodMarshalAPERTo(v *ExpectedUEActivityBehaviourExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(v *ExpectedUEActivityBehaviourExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldCapture(v *ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) *func(ExpectedUEActivityBehaviourExtIEsExtField, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldCompare(v *ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) *func(ExpectedUEActivityBehaviourExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldContext(v *ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldDecode(v *ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ExpectedUEActivityBehaviourExtIEsExtField, error) {
	return &v.decode
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldEncode(v *ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) *func(ExpectedUEActivityBehaviourExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldPath(v *ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldCapture(v *ExpectedUEBehaviourExtIEsExtContainerValueCodec) *func(ExpectedUEBehaviourExtIEsExtContainer, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldCompare(v *ExpectedUEBehaviourExtIEsExtContainerValueCodec) *func(ExpectedUEBehaviourExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldContext(v *ExpectedUEBehaviourExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldDecode(v *ExpectedUEBehaviourExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldEncode(v *ExpectedUEBehaviourExtIEsExtContainerValueCodec) *func(ExpectedUEBehaviourExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldPath(v *ExpectedUEBehaviourExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeExpectedUEBehaviourExtIEsExtFieldFieldReplay(v *ExpectedUEBehaviourExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeExpectedUEBehaviourExtIEsExtFieldFieldWithoutReplay(v *ExpectedUEBehaviourExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeExpectedUEBehaviourExtIEsExtFieldMethodMarshalAPERTo(v *ExpectedUEBehaviourExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeExpectedUEBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(v *ExpectedUEBehaviourExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldCapture(v *ExpectedUEBehaviourExtIEsExtFieldValueCodec) *func(ExpectedUEBehaviourExtIEsExtField, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldCompare(v *ExpectedUEBehaviourExtIEsExtFieldValueCodec) *func(ExpectedUEBehaviourExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldContext(v *ExpectedUEBehaviourExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldDecode(v *ExpectedUEBehaviourExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ExpectedUEBehaviourExtIEsExtField, error) {
	return &v.decode
}
func BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldEncode(v *ExpectedUEBehaviourExtIEsExtFieldValueCodec) *func(ExpectedUEBehaviourExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldPath(v *ExpectedUEBehaviourExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldCapture(v *FiveGSTAIExtIEsExtContainerValueCodec) *func(FiveGSTAIExtIEsExtContainer, aper.DecodeState) (FiveGSTAIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldCompare(v *FiveGSTAIExtIEsExtContainerValueCodec) *func(FiveGSTAIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldContext(v *FiveGSTAIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldDecode(v *FiveGSTAIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (FiveGSTAIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldEncode(v *FiveGSTAIExtIEsExtContainerValueCodec) *func(FiveGSTAIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldPath(v *FiveGSTAIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeFiveGSTAIExtIEsExtFieldFieldReplay(v *FiveGSTAIExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeFiveGSTAIExtIEsExtFieldFieldWithoutReplay(v *FiveGSTAIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeFiveGSTAIExtIEsExtFieldMethodMarshalAPERTo(v *FiveGSTAIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeFiveGSTAIExtIEsExtFieldMethodUnmarshalAPERFrom(v *FiveGSTAIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldCapture(v *FiveGSTAIExtIEsExtFieldValueCodec) *func(FiveGSTAIExtIEsExtField, aper.DecodeState) (FiveGSTAIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldCompare(v *FiveGSTAIExtIEsExtFieldValueCodec) *func(FiveGSTAIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldContext(v *FiveGSTAIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldDecode(v *FiveGSTAIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (FiveGSTAIExtIEsExtField, error) {
	return &v.decode
}
func BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldEncode(v *FiveGSTAIExtIEsExtFieldValueCodec) *func(FiveGSTAIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldPath(v *FiveGSTAIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldCapture(v *ForbiddenLAsItemExtIEsExtContainerValueCodec) *func(ForbiddenLAsItemExtIEsExtContainer, aper.DecodeState) (ForbiddenLAsItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldCompare(v *ForbiddenLAsItemExtIEsExtContainerValueCodec) *func(ForbiddenLAsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldContext(v *ForbiddenLAsItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldDecode(v *ForbiddenLAsItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ForbiddenLAsItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldEncode(v *ForbiddenLAsItemExtIEsExtContainerValueCodec) *func(ForbiddenLAsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldPath(v *ForbiddenLAsItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeForbiddenLAsItemExtIEsExtFieldFieldReplay(v *ForbiddenLAsItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenLAsItemExtIEsExtFieldFieldWithoutReplay(v *ForbiddenLAsItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenLAsItemExtIEsExtFieldMethodMarshalAPERTo(v *ForbiddenLAsItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeForbiddenLAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ForbiddenLAsItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldCapture(v *ForbiddenLAsItemExtIEsExtFieldValueCodec) *func(ForbiddenLAsItemExtIEsExtField, aper.DecodeState) (ForbiddenLAsItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldCompare(v *ForbiddenLAsItemExtIEsExtFieldValueCodec) *func(ForbiddenLAsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldContext(v *ForbiddenLAsItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldDecode(v *ForbiddenLAsItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ForbiddenLAsItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldEncode(v *ForbiddenLAsItemExtIEsExtFieldValueCodec) *func(ForbiddenLAsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldPath(v *ForbiddenLAsItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldCapture(v *ForbiddenTAsItemExtIEsExtContainerValueCodec) *func(ForbiddenTAsItemExtIEsExtContainer, aper.DecodeState) (ForbiddenTAsItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldCompare(v *ForbiddenTAsItemExtIEsExtContainerValueCodec) *func(ForbiddenTAsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldContext(v *ForbiddenTAsItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldDecode(v *ForbiddenTAsItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ForbiddenTAsItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldEncode(v *ForbiddenTAsItemExtIEsExtContainerValueCodec) *func(ForbiddenTAsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldPath(v *ForbiddenTAsItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeForbiddenTAsItemExtIEsExtFieldFieldReplay(v *ForbiddenTAsItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenTAsItemExtIEsExtFieldFieldWithoutReplay(v *ForbiddenTAsItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenTAsItemExtIEsExtFieldMethodMarshalAPERTo(v *ForbiddenTAsItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeForbiddenTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ForbiddenTAsItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldCapture(v *ForbiddenTAsItemExtIEsExtFieldValueCodec) *func(ForbiddenTAsItemExtIEsExtField, aper.DecodeState) (ForbiddenTAsItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldCompare(v *ForbiddenTAsItemExtIEsExtFieldValueCodec) *func(ForbiddenTAsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldContext(v *ForbiddenTAsItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldDecode(v *ForbiddenTAsItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ForbiddenTAsItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldEncode(v *ForbiddenTAsItemExtIEsExtFieldValueCodec) *func(ForbiddenTAsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldPath(v *ForbiddenTAsItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABQoSParametersExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 273:
		if value, ok := v.AsDownlinkPacketLossRate(); ok {
			return value, true
		}
	case 274:
		if value, ok := v.AsUplinkPacketLossRate(); ok {
			return value, true
		}
	}
	return nil, false
}
