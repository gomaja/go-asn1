// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s13 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s13

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ServedDCNsItemExtIEsExtContainer is ProtocolExtensionContainer {{ServedDCNsItem-ExtIEs}} of TS 36.413: a list of ServedDCNsItemExtIEsExtField values.
type ServedDCNsItemExtIEsExtContainer []ServedDCNsItemExtIEsExtField

// RequestedTNLInfoExtIEsExtContainer is ProtocolExtensionContainer {{RequestedTNLInfo-ExtIEs}} of TS 36.413: a list of RequestedTNLInfoExtIEsExtField values.
type RequestedTNLInfoExtIEsExtContainer []RequestedTNLInfoExtIEsExtField

// SecurityContextExtIEsExtContainer is ProtocolExtensionContainer {{SecurityContext-ExtIEs}} of TS 36.413: a list of SecurityContextExtIEsExtField values.
type SecurityContextExtIEsExtContainer []SecurityContextExtIEsExtField

// SecondaryRATDataUsageReportItemExtIEsExtContainer is ProtocolExtensionContainer {{SecondaryRATDataUsageReportItem-ExtIEs}} of TS 36.413: a list of SecondaryRATDataUsageReportItemExtIEsExtField values.
type SecondaryRATDataUsageReportItemExtIEsExtContainer []SecondaryRATDataUsageReportItemExtIEsExtField

// SecurityIndicationExtIEsExtContainer is ProtocolExtensionContainer {{SecurityIndication-ExtIEs}} of TS 36.413: a list of SecurityIndicationExtIEsExtField values.
type SecurityIndicationExtIEsExtContainer []SecurityIndicationExtIEsExtField

// SecurityResultExtIEsExtContainer is ProtocolExtensionContainer {{SecurityResult-ExtIEs}} of TS 36.413: a list of SecurityResultExtIEsExtField values.
type SecurityResultExtIEsExtContainer []SecurityResultExtIEsExtField

// SensorMeasConfigNameItemExtIEsExtContainer is ProtocolExtensionContainer {{SensorMeasConfigNameItem-ExtIEs}} of TS 36.413: a list of SensorMeasConfigNameItemExtIEsExtField values.
type SensorMeasConfigNameItemExtIEsExtContainer []SensorMeasConfigNameItemExtIEsExtField

// SensorMeasurementConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{SensorMeasurementConfiguration-ExtIEs}} of TS 36.413: a list of SensorMeasurementConfigurationExtIEsExtField values.
type SensorMeasurementConfigurationExtIEsExtContainer []SensorMeasurementConfigurationExtIEsExtField

// SensorNameConfigExtIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{SensorNameConfig-ExtIEs}} of TS 36.413: a single information element field.
type SensorNameConfigExtIEValueProtocolIESingleContainer = SensorNameConfigExtIEField

// SynchronisationInformationExtIEsExtContainer is ProtocolExtensionContainer {{SynchronisationInformation-ExtIEs}} of TS 36.413: a list of SynchronisationInformationExtIEsExtField values.
type SynchronisationInformationExtIEsExtContainer []SynchronisationInformationExtIEsExtField

// SourceeNBIDExtIEsExtContainer is ProtocolExtensionContainer {{SourceeNB-ID-ExtIEs}} of TS 36.413: a list of SourceeNBIDExtIEsExtField values.
type SourceeNBIDExtIEsExtContainer []SourceeNBIDExtIEsExtField

// SourceNgRanNodeIDExtIEsExtContainer is ProtocolExtensionContainer {{SourceNgRanNode-ID-ExtIEs}} of TS 36.413: a list of SourceNgRanNodeIDExtIEsExtField values.
type SourceNgRanNodeIDExtIEsExtContainer []SourceNgRanNodeIDExtIEsExtField

// ServedGUMMEIsItemExtIEsExtContainer is ProtocolExtensionContainer {{ServedGUMMEIsItem-ExtIEs}} of TS 36.413: a list of ServedGUMMEIsItemExtIEsExtField values.
type ServedGUMMEIsItemExtIEsExtContainer []ServedGUMMEIsItemExtIEsExtField

// SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer is ProtocolExtensionContainer {{Subscription-Based-UE-DifferentiationInfo-ExtIEs}} of TS 36.413: a list of SubscriptionBasedUEDifferentiationInfoExtIEsExtField values.
type SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer []SubscriptionBasedUEDifferentiationInfoExtIEsExtField

// ScheduledCommunicationTimeExtIEsExtContainer is ProtocolExtensionContainer {{ScheduledCommunicationTime-ExtIEs}} of TS 36.413: a list of ScheduledCommunicationTimeExtIEsExtField values.
type ScheduledCommunicationTimeExtIEsExtContainer []ScheduledCommunicationTimeExtIEsExtField

// SupportedTAsItemExtIEsExtContainer is ProtocolExtensionContainer {{SupportedTAs-Item-ExtIEs}} of TS 36.413: a list of SupportedTAsItemExtIEsExtField values.
type SupportedTAsItemExtIEsExtContainer []SupportedTAsItemExtIEsExtField

// TimeSynchronisationInfoExtIEsExtContainer is ProtocolExtensionContainer {{TimeSynchronisationInfo-ExtIEs}} of TS 36.413: a list of TimeSynchronisationInfoExtIEsExtField values.
type TimeSynchronisationInfoExtIEsExtContainer []TimeSynchronisationInfoExtIEsExtField

// STMSIExtIEsExtContainer is ProtocolExtensionContainer {{S-TMSI-ExtIEs}} of TS 36.413: a list of STMSIExtIEsExtField values.
type STMSIExtIEsExtContainer []STMSIExtIEsExtField

// TAIBasedMDTExtIEsExtContainer is ProtocolExtensionContainer {{TAIBasedMDT-ExtIEs}} of TS 36.413: a list of TAIBasedMDTExtIEsExtField values.
type TAIBasedMDTExtIEsExtContainer []TAIBasedMDTExtIEsExtField

// TAIExtIEsExtContainer is ProtocolExtensionContainer {{TAI-ExtIEs}} of TS 36.413: a list of TAIExtIEsExtField values.
type TAIExtIEsExtContainer []TAIExtIEsExtField

// TAIBroadcastItemExtIEsExtContainer is ProtocolExtensionContainer {{TAI-Broadcast-Item-ExtIEs}} of TS 36.413: a list of TAIBroadcastItemExtIEsExtField values.
type TAIBroadcastItemExtIEsExtContainer []TAIBroadcastItemExtIEsExtField

// TAICancelledItemExtIEsExtContainer is ProtocolExtensionContainer {{TAI-Cancelled-Item-ExtIEs}} of TS 36.413: a list of TAICancelledItemExtIEsExtField values.
type TAICancelledItemExtIEsExtContainer []TAICancelledItemExtIEsExtField

// TABasedMDTExtIEsExtContainer is ProtocolExtensionContainer {{TABasedMDT-ExtIEs}} of TS 36.413: a list of TABasedMDTExtIEsExtField values.
type TABasedMDTExtIEsExtContainer []TABasedMDTExtIEsExtField

// TABasedQMCExtIEsExtContainer is ProtocolExtensionContainer {{TABasedQMC-ExtIEs}} of TS 36.413: a list of TABasedQMCExtIEsExtField values.
type TABasedQMCExtIEsExtContainer []TABasedQMCExtIEsExtField

// TAIBasedQMCExtIEsExtContainer is ProtocolExtensionContainer {{TAIBasedQMC-ExtIEs}} of TS 36.413: a list of TAIBasedQMCExtIEsExtField values.
type TAIBasedQMCExtIEsExtContainer []TAIBasedQMCExtIEsExtField

// TargeteNBIDExtIEsExtContainer is ProtocolExtensionContainer {{TargeteNB-ID-ExtIEs}} of TS 36.413: a list of TargeteNBIDExtIEsExtField values.
type TargeteNBIDExtIEsExtContainer []TargeteNBIDExtIEsExtField

// TargetRNCIDExtIEsExtContainer is ProtocolExtensionContainer {{TargetRNC-ID-ExtIEs}} of TS 36.413: a list of TargetRNCIDExtIEsExtField values.
type TargetRNCIDExtIEsExtContainer []TargetRNCIDExtIEsExtField

// TargetNgRanNodeIDExtIEsExtContainer is ProtocolExtensionContainer {{TargetNgRanNode-ID-ExtIEs}} of TS 36.413: a list of TargetNgRanNodeIDExtIEsExtField values.
type TargetNgRanNodeIDExtIEsExtContainer []TargetNgRanNodeIDExtIEsExtField

// TimeBasedHandoverInformationExtIEsExtContainer is ProtocolExtensionContainer {{TimeBasedHandoverInformation-ExtIEs}} of TS 36.413: a list of TimeBasedHandoverInformationExtIEsExtField values.
type TimeBasedHandoverInformationExtIEsExtContainer []TimeBasedHandoverInformationExtIEsExtField

// ServedDCNsItemExtIEsExtField is ProtocolExtensionField {{ServedDCNsItem-ExtIEs}} of TS 36.413: an extension field.
type ServedDCNsItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.ServedDCNsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedDCNsItemExtIEsExtField) WithoutReplay() ServedDCNsItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ServedDCNsItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ServedDCNsItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeServedDCNsItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeServedDCNsItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ServedDCNsItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedDCNsItemExtIEsExtField{}
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
	var zero s07.ServedDCNsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeServedDCNsItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeServedDCNsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeServedDCNsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RequestedTNLInfoExtIEsExtField is ProtocolExtensionField {{RequestedTNLInfo-ExtIEs}} of TS 36.413: an extension field.
type RequestedTNLInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RequestedTNLInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestedTNLInfoExtIEsExtField) WithoutReplay() RequestedTNLInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RequestedTNLInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RequestedTNLInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeRequestedTNLInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRequestedTNLInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RequestedTNLInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestedTNLInfoExtIEsExtField{}
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
	var zero s06.RequestedTNLInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRequestedTNLInfoExtIEsValueMethodReason(zero, v.Id), s06.BridgeRequestedTNLInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRequestedTNLInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecurityContextExtIEsExtField is ProtocolExtensionField {{SecurityContext-ExtIEs}} of TS 36.413: an extension field.
type SecurityContextExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.SecurityContextExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityContextExtIEsExtField) WithoutReplay() SecurityContextExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecurityContextExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecurityContextExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecurityContextExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecurityContextExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecurityContextExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityContextExtIEsExtField{}
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
	var zero s06.SecurityContextExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecurityContextExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecurityContextExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeSecurityContextExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecondaryRATDataUsageReportItemExtIEsExtField is ProtocolExtensionField {{SecondaryRATDataUsageReportItem-ExtIEs}} of TS 36.413: an extension field.
type SecondaryRATDataUsageReportItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.SecondaryRATDataUsageReportItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemExtIEsExtField) WithoutReplay() SecondaryRATDataUsageReportItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecondaryRATDataUsageReportItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecondaryRATDataUsageReportItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecondaryRATDataUsageReportItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecondaryRATDataUsageReportItemExtIEsExtField{}
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
	var zero s06.SecondaryRATDataUsageReportItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecurityIndicationExtIEsExtField is ProtocolExtensionField {{SecurityIndication-ExtIEs}} of TS 36.413: an extension field.
type SecurityIndicationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.SecurityIndicationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityIndicationExtIEsExtField) WithoutReplay() SecurityIndicationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecurityIndicationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecurityIndicationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecurityIndicationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecurityIndicationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecurityIndicationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityIndicationExtIEsExtField{}
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
	var zero s06.SecurityIndicationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecurityIndicationExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecurityIndicationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeSecurityIndicationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecurityResultExtIEsExtField is ProtocolExtensionField {{SecurityResult-ExtIEs}} of TS 36.413: an extension field.
type SecurityResultExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.SecurityResultExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityResultExtIEsExtField) WithoutReplay() SecurityResultExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecurityResultExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecurityResultExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecurityResultExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecurityResultExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecurityResultExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityResultExtIEsExtField{}
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
	var zero s06.SecurityResultExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecurityResultExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecurityResultExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeSecurityResultExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SensorMeasConfigNameItemExtIEsExtField is ProtocolExtensionField {{SensorMeasConfigNameItem-ExtIEs}} of TS 36.413: an extension field.
type SensorMeasConfigNameItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.SensorMeasConfigNameItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasConfigNameItemExtIEsExtField) WithoutReplay() SensorMeasConfigNameItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SensorMeasConfigNameItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SensorMeasConfigNameItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SensorMeasConfigNameItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasConfigNameItemExtIEsExtField{}
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
	var zero s06.SensorMeasConfigNameItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SensorMeasurementConfigurationExtIEsExtField is ProtocolExtensionField {{SensorMeasurementConfiguration-ExtIEs}} of TS 36.413: an extension field.
type SensorMeasurementConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.SensorMeasurementConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasurementConfigurationExtIEsExtField) WithoutReplay() SensorMeasurementConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SensorMeasurementConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SensorMeasurementConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SensorMeasurementConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasurementConfigurationExtIEsExtField{}
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
	var zero s07.SensorMeasurementConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodReason(zero, v.Id), s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SynchronisationInformationExtIEsExtField is ProtocolExtensionField {{SynchronisationInformation-ExtIEs}} of TS 36.413: an extension field.
type SynchronisationInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.SynchronisationInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SynchronisationInformationExtIEsExtField) WithoutReplay() SynchronisationInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SynchronisationInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SynchronisationInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSynchronisationInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSynchronisationInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SynchronisationInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SynchronisationInformationExtIEsExtField{}
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
	var zero s07.SynchronisationInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSynchronisationInformationExtIEsValueMethodReason(zero, v.Id), s07.BridgeSynchronisationInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeSynchronisationInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SourceeNBIDExtIEsExtField is ProtocolExtensionField {{SourceeNB-ID-ExtIEs}} of TS 36.413: an extension field.
type SourceeNBIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.SourceeNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBIDExtIEsExtField) WithoutReplay() SourceeNBIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SourceeNBIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SourceeNBIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSourceeNBIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSourceeNBIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SourceeNBIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceeNBIDExtIEsExtField{}
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
	var zero s07.SourceeNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSourceeNBIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeSourceeNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeSourceeNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SourceNgRanNodeIDExtIEsExtField is ProtocolExtensionField {{SourceNgRanNode-ID-ExtIEs}} of TS 36.413: an extension field.
type SourceNgRanNodeIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.SourceNgRanNodeIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNgRanNodeIDExtIEsExtField) WithoutReplay() SourceNgRanNodeIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SourceNgRanNodeIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SourceNgRanNodeIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSourceNgRanNodeIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSourceNgRanNodeIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SourceNgRanNodeIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNgRanNodeIDExtIEsExtField{}
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
	var zero s07.SourceNgRanNodeIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSourceNgRanNodeIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeSourceNgRanNodeIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeSourceNgRanNodeIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ServedGUMMEIsItemExtIEsExtField is ProtocolExtensionField {{ServedGUMMEIsItem-ExtIEs}} of TS 36.413: an extension field.
type ServedGUMMEIsItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.ServedGUMMEIsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedGUMMEIsItemExtIEsExtField) WithoutReplay() ServedGUMMEIsItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ServedGUMMEIsItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ServedGUMMEIsItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeServedGUMMEIsItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeServedGUMMEIsItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ServedGUMMEIsItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedGUMMEIsItemExtIEsExtField{}
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
	var zero s07.ServedGUMMEIsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeServedGUMMEIsItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeServedGUMMEIsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeServedGUMMEIsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SubscriptionBasedUEDifferentiationInfoExtIEsExtField is ProtocolExtensionField {{Subscription-Based-UE-DifferentiationInfo-ExtIEs}} of TS 36.413: an extension field.
type SubscriptionBasedUEDifferentiationInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SubscriptionBasedUEDifferentiationInfoExtIEsExtField) WithoutReplay() SubscriptionBasedUEDifferentiationInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SubscriptionBasedUEDifferentiationInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SubscriptionBasedUEDifferentiationInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SubscriptionBasedUEDifferentiationInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SubscriptionBasedUEDifferentiationInfoExtIEsExtField{}
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
	var zero s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodReason(zero, v.Id), s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ScheduledCommunicationTimeExtIEsExtField is ProtocolExtensionField {{ScheduledCommunicationTime-ExtIEs}} of TS 36.413: an extension field.
type ScheduledCommunicationTimeExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.ScheduledCommunicationTimeExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ScheduledCommunicationTimeExtIEsExtField) WithoutReplay() ScheduledCommunicationTimeExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ScheduledCommunicationTimeExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ScheduledCommunicationTimeExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeScheduledCommunicationTimeExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeScheduledCommunicationTimeExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ScheduledCommunicationTimeExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ScheduledCommunicationTimeExtIEsExtField{}
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
	var zero s06.ScheduledCommunicationTimeExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeScheduledCommunicationTimeExtIEsValueMethodReason(zero, v.Id), s06.BridgeScheduledCommunicationTimeExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeScheduledCommunicationTimeExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SupportedTAsItemExtIEsExtField is ProtocolExtensionField {{SupportedTAs-Item-ExtIEs}} of TS 36.413: an extension field.
type SupportedTAsItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s08.SupportedTAsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsItemExtIEsExtField) WithoutReplay() SupportedTAsItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SupportedTAsItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SupportedTAsItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s08.BridgeSupportedTAsItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s08.BridgeSupportedTAsItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SupportedTAsItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SupportedTAsItemExtIEsExtField{}
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
	var zero s08.SupportedTAsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s08.BridgeSupportedTAsItemExtIEsValueMethodReason(zero, v.Id), s08.BridgeSupportedTAsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s08.BridgeSupportedTAsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TimeSynchronisationInfoExtIEsExtField is ProtocolExtensionField {{TimeSynchronisationInfo-ExtIEs}} of TS 36.413: an extension field.
type TimeSynchronisationInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TimeSynchronisationInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeSynchronisationInfoExtIEsExtField) WithoutReplay() TimeSynchronisationInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TimeSynchronisationInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TimeSynchronisationInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTimeSynchronisationInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTimeSynchronisationInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TimeSynchronisationInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TimeSynchronisationInfoExtIEsExtField{}
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
	var zero s07.TimeSynchronisationInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTimeSynchronisationInfoExtIEsValueMethodReason(zero, v.Id), s07.BridgeTimeSynchronisationInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTimeSynchronisationInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// STMSIExtIEsExtField is ProtocolExtensionField {{S-TMSI-ExtIEs}} of TS 36.413: an extension field.
type STMSIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.STMSIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v STMSIExtIEsExtField) WithoutReplay() STMSIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *STMSIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *STMSIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSTMSIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSTMSIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *STMSIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = STMSIExtIEsExtField{}
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
	var zero s06.STMSIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSTMSIExtIEsValueMethodReason(zero, v.Id), s06.BridgeSTMSIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeSTMSIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIBasedMDTExtIEsExtField is ProtocolExtensionField {{TAIBasedMDT-ExtIEs}} of TS 36.413: an extension field.
type TAIBasedMDTExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TAIBasedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedMDTExtIEsExtField) WithoutReplay() TAIBasedMDTExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIBasedMDTExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIBasedMDTExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIBasedMDTExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIBasedMDTExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIBasedMDTExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedMDTExtIEsExtField{}
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
	var zero s07.TAIBasedMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIBasedMDTExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIBasedMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTAIBasedMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIExtIEsExtField is ProtocolExtensionField {{TAI-ExtIEs}} of TS 36.413: an extension field.
type TAIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TAIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIExtIEsExtField) WithoutReplay() TAIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIExtIEsExtField{}
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
	var zero s07.TAIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTAIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIBroadcastItemExtIEsExtField is ProtocolExtensionField {{TAI-Broadcast-Item-ExtIEs}} of TS 36.413: an extension field.
type TAIBroadcastItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TAIBroadcastItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBroadcastItemExtIEsExtField) WithoutReplay() TAIBroadcastItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIBroadcastItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIBroadcastItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIBroadcastItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIBroadcastItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIBroadcastItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBroadcastItemExtIEsExtField{}
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
	var zero s07.TAIBroadcastItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIBroadcastItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIBroadcastItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTAIBroadcastItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAICancelledItemExtIEsExtField is ProtocolExtensionField {{TAI-Cancelled-Item-ExtIEs}} of TS 36.413: an extension field.
type TAICancelledItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TAICancelledItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAICancelledItemExtIEsExtField) WithoutReplay() TAICancelledItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAICancelledItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAICancelledItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAICancelledItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAICancelledItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAICancelledItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAICancelledItemExtIEsExtField{}
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
	var zero s07.TAICancelledItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAICancelledItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAICancelledItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTAICancelledItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TABasedMDTExtIEsExtField is ProtocolExtensionField {{TABasedMDT-ExtIEs}} of TS 36.413: an extension field.
type TABasedMDTExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TABasedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedMDTExtIEsExtField) WithoutReplay() TABasedMDTExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TABasedMDTExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TABasedMDTExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTABasedMDTExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTABasedMDTExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TABasedMDTExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TABasedMDTExtIEsExtField{}
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
	var zero s07.TABasedMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTABasedMDTExtIEsValueMethodReason(zero, v.Id), s07.BridgeTABasedMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTABasedMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TABasedQMCExtIEsExtField is ProtocolExtensionField {{TABasedQMC-ExtIEs}} of TS 36.413: an extension field.
type TABasedQMCExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TABasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedQMCExtIEsExtField) WithoutReplay() TABasedQMCExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TABasedQMCExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TABasedQMCExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTABasedQMCExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTABasedQMCExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TABasedQMCExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TABasedQMCExtIEsExtField{}
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
	var zero s07.TABasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTABasedQMCExtIEsValueMethodReason(zero, v.Id), s07.BridgeTABasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTABasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIBasedQMCExtIEsExtField is ProtocolExtensionField {{TAIBasedQMC-ExtIEs}} of TS 36.413: an extension field.
type TAIBasedQMCExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TAIBasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedQMCExtIEsExtField) WithoutReplay() TAIBasedQMCExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIBasedQMCExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIBasedQMCExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIBasedQMCExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIBasedQMCExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIBasedQMCExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedQMCExtIEsExtField{}
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
	var zero s07.TAIBasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIBasedQMCExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIBasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTAIBasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TargeteNBIDExtIEsExtField is ProtocolExtensionField {{TargeteNB-ID-ExtIEs}} of TS 36.413: an extension field.
type TargeteNBIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TargeteNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBIDExtIEsExtField) WithoutReplay() TargeteNBIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargeteNBIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargeteNBIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTargeteNBIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTargeteNBIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TargeteNBIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargeteNBIDExtIEsExtField{}
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
	var zero s07.TargeteNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTargeteNBIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeTargeteNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTargeteNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TargetRNCIDExtIEsExtField is ProtocolExtensionField {{TargetRNC-ID-ExtIEs}} of TS 36.413: an extension field.
type TargetRNCIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TargetRNCIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetRNCIDExtIEsExtField) WithoutReplay() TargetRNCIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargetRNCIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargetRNCIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTargetRNCIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTargetRNCIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TargetRNCIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargetRNCIDExtIEsExtField{}
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
	var zero s07.TargetRNCIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTargetRNCIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeTargetRNCIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTargetRNCIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TargetNgRanNodeIDExtIEsExtField is ProtocolExtensionField {{TargetNgRanNode-ID-ExtIEs}} of TS 36.413: an extension field.
type TargetNgRanNodeIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TargetNgRanNodeIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetNgRanNodeIDExtIEsExtField) WithoutReplay() TargetNgRanNodeIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargetNgRanNodeIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargetNgRanNodeIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTargetNgRanNodeIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTargetNgRanNodeIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TargetNgRanNodeIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargetNgRanNodeIDExtIEsExtField{}
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
	var zero s07.TargetNgRanNodeIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTargetNgRanNodeIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeTargetNgRanNodeIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTargetNgRanNodeIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TimeBasedHandoverInformationExtIEsExtField is ProtocolExtensionField {{TimeBasedHandoverInformation-ExtIEs}} of TS 36.413: an extension field.
type TimeBasedHandoverInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TimeBasedHandoverInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeBasedHandoverInformationExtIEsExtField) WithoutReplay() TimeBasedHandoverInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TimeBasedHandoverInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TimeBasedHandoverInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TimeBasedHandoverInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TimeBasedHandoverInformationExtIEsExtField{}
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
	var zero s07.TimeBasedHandoverInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodReason(zero, v.Id), s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIItemExtIEsExtContainer is ProtocolExtensionContainer {{TAIItemExtIEs}} of TS 36.413: a list of TAIItemExtIEsExtField values.
type TAIItemExtIEsExtContainer []TAIItemExtIEsExtField

// TAIItemExtIEsExtField is ProtocolExtensionField {{TAIItemExtIEs}} of TS 36.413: an extension field.
type TAIItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s07.TAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemExtIEsExtField) WithoutReplay() TAIItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIItemExtIEsExtField{}
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
	var zero s07.TAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s07.BridgeTAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SensorNameConfigExtIEField is ProtocolIE-Field {{SensorNameConfig-ExtIEs}} of TS 36.413: an information element field.
type SensorNameConfigExtIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.SensorNameConfigExtIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorNameConfigExtIEField) WithoutReplay() SensorNameConfigExtIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SensorNameConfigExtIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SensorNameConfigExtIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSensorNameConfigExtIEValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSensorNameConfigExtIEValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SensorNameConfigExtIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorNameConfigExtIEField{}
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
	var zero s07.SensorNameConfigExtIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSensorNameConfigExtIEValueMethodReason(zero, v.Id), s07.BridgeSensorNameConfigExtIEValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeSensorNameConfigExtIEValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding binds GUMMEIType to the ServedGUMMEIsItem-ExtIEs object set of TS 36.413.
type ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.GUMMEITypeValueCodec
	inject func(s00.GUMMEIType,

	) s07.ServedGUMMEIsItemExtIEsValue

	get func(*s07.ServedGUMMEIsItemExtIEsValue,

	) (*s00.GUMMEIType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding) Codec() s01.GUMMEITypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding) New(value s00.GUMMEIType,

) (ServedGUMMEIsItemExtIEsExtField, error) {
	if b.inject == nil {
		return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeGUMMEITypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ServedGUMMEIsItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding) Get(field *ServedGUMMEIsItemExtIEsExtField) (*s00.GUMMEIType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceNodeIDExtensionIEIEField is ProtocolIE-Field {{SourceNodeID-ExtensionIE}} of TS 36.413: an information element field.
type SourceNodeIDExtensionIEIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.SourceNodeIDExtensionIEIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionIEIEField) WithoutReplay() SourceNodeIDExtensionIEIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SourceNodeIDExtensionIEIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SourceNodeIDExtensionIEIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSourceNodeIDExtensionIEIEValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSourceNodeIDExtensionIEIEValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SourceNodeIDExtensionIEIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNodeIDExtensionIEIEField{}
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
	var zero s07.SourceNodeIDExtensionIEIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSourceNodeIDExtensionIEIEValueMethodReason(zero, v.Id), s07.BridgeSourceNodeIDExtensionIEIEValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeSourceNodeIDExtensionIEIEValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SupportedTAsItemExtIEsRATTypeExtBinding binds RATType to the SupportedTAs-Item-ExtIEs object set of TS 36.413.
type SupportedTAsItemExtIEsRATTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.RATTypeValueCodec
	inject func(s00.RATType,

	) s08.SupportedTAsItemExtIEsValue

	get func(*s08.SupportedTAsItemExtIEsValue,

	) (*s00.RATType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SupportedTAsItemExtIEsRATTypeExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SupportedTAsItemExtIEsRATTypeExtBinding) Codec() s01.RATTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b SupportedTAsItemExtIEsRATTypeExtBinding) New(value s00.RATType,

) (SupportedTAsItemExtIEsExtField, error) {
	if b.inject == nil {
		return SupportedTAsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SupportedTAsItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRATTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SupportedTAsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SupportedTAsItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SupportedTAsItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SupportedTAsItemExtIEsRATTypeExtBinding) Get(field *SupportedTAsItemExtIEsExtField) (*s00.RATType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// RequestedTNLInfoExtIEsIEField uses the ProtocolIE-Field shape for object set RequestedTNLInfo-ExtIEs of TS 36.413.
type RequestedTNLInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RequestedTNLInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestedTNLInfoExtIEsIEField) WithoutReplay() RequestedTNLInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RequestedTNLInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RequestedTNLInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeRequestedTNLInfoExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRequestedTNLInfoExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RequestedTNLInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestedTNLInfoExtIEsIEField{}
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
	var zero s06.RequestedTNLInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRequestedTNLInfoExtIEsValueMethodReason(zero, v.Id), s06.BridgeRequestedTNLInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRequestedTNLInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RequestedTNLInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set RequestedTNLInfo-ExtIEs of TS 36.413: a list of RequestedTNLInfoExtIEsIEField values.
type RequestedTNLInfoExtIEsIEContainer []RequestedTNLInfoExtIEsIEField

// STMSIExtIEsIEField uses the ProtocolIE-Field shape for object set S-TMSI-ExtIEs of TS 36.413.
type STMSIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.STMSIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v STMSIExtIEsIEField) WithoutReplay() STMSIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *STMSIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *STMSIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSTMSIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSTMSIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *STMSIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = STMSIExtIEsIEField{}
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
	var zero s06.STMSIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSTMSIExtIEsValueMethodReason(zero, v.Id), s06.BridgeSTMSIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeSTMSIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// STMSIExtIEsIEContainer uses the ProtocolIE-Container shape for object set S-TMSI-ExtIEs of TS 36.413: a list of STMSIExtIEsIEField values.
type STMSIExtIEsIEContainer []STMSIExtIEsIEField

// ScheduledCommunicationTimeExtIEsIEField uses the ProtocolIE-Field shape for object set ScheduledCommunicationTime-ExtIEs of TS 36.413.
type ScheduledCommunicationTimeExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.ScheduledCommunicationTimeExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ScheduledCommunicationTimeExtIEsIEField) WithoutReplay() ScheduledCommunicationTimeExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ScheduledCommunicationTimeExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ScheduledCommunicationTimeExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeScheduledCommunicationTimeExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeScheduledCommunicationTimeExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ScheduledCommunicationTimeExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ScheduledCommunicationTimeExtIEsIEField{}
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
	var zero s06.ScheduledCommunicationTimeExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeScheduledCommunicationTimeExtIEsValueMethodReason(zero, v.Id), s06.BridgeScheduledCommunicationTimeExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeScheduledCommunicationTimeExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ScheduledCommunicationTimeExtIEsIEContainer uses the ProtocolIE-Container shape for object set ScheduledCommunicationTime-ExtIEs of TS 36.413: a list of ScheduledCommunicationTimeExtIEsIEField values.
type ScheduledCommunicationTimeExtIEsIEContainer []ScheduledCommunicationTimeExtIEsIEField

// SecondaryRATDataUsageReportItemExtIEsIEField uses the ProtocolIE-Field shape for object set SecondaryRATDataUsageReportItem-ExtIEs of TS 36.413.
type SecondaryRATDataUsageReportItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.SecondaryRATDataUsageReportItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemExtIEsIEField) WithoutReplay() SecondaryRATDataUsageReportItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecondaryRATDataUsageReportItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecondaryRATDataUsageReportItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecondaryRATDataUsageReportItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecondaryRATDataUsageReportItemExtIEsIEField{}
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
	var zero s06.SecondaryRATDataUsageReportItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecondaryRATDataUsageReportItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set SecondaryRATDataUsageReportItem-ExtIEs of TS 36.413: a list of SecondaryRATDataUsageReportItemExtIEsIEField values.
type SecondaryRATDataUsageReportItemExtIEsIEContainer []SecondaryRATDataUsageReportItemExtIEsIEField

// SecurityContextExtIEsIEField uses the ProtocolIE-Field shape for object set SecurityContext-ExtIEs of TS 36.413.
type SecurityContextExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.SecurityContextExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityContextExtIEsIEField) WithoutReplay() SecurityContextExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecurityContextExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecurityContextExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecurityContextExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecurityContextExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecurityContextExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityContextExtIEsIEField{}
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
	var zero s06.SecurityContextExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecurityContextExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecurityContextExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeSecurityContextExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecurityContextExtIEsIEContainer uses the ProtocolIE-Container shape for object set SecurityContext-ExtIEs of TS 36.413: a list of SecurityContextExtIEsIEField values.
type SecurityContextExtIEsIEContainer []SecurityContextExtIEsIEField

// SecurityIndicationExtIEsIEField uses the ProtocolIE-Field shape for object set SecurityIndication-ExtIEs of TS 36.413.
type SecurityIndicationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.SecurityIndicationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityIndicationExtIEsIEField) WithoutReplay() SecurityIndicationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecurityIndicationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecurityIndicationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecurityIndicationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecurityIndicationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecurityIndicationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityIndicationExtIEsIEField{}
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
	var zero s06.SecurityIndicationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecurityIndicationExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecurityIndicationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeSecurityIndicationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecurityIndicationExtIEsIEContainer uses the ProtocolIE-Container shape for object set SecurityIndication-ExtIEs of TS 36.413: a list of SecurityIndicationExtIEsIEField values.
type SecurityIndicationExtIEsIEContainer []SecurityIndicationExtIEsIEField

// SecurityResultExtIEsIEField uses the ProtocolIE-Field shape for object set SecurityResult-ExtIEs of TS 36.413.
type SecurityResultExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.SecurityResultExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityResultExtIEsIEField) WithoutReplay() SecurityResultExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecurityResultExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecurityResultExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSecurityResultExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSecurityResultExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SecurityResultExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityResultExtIEsIEField{}
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
	var zero s06.SecurityResultExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSecurityResultExtIEsValueMethodReason(zero, v.Id), s06.BridgeSecurityResultExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeSecurityResultExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SecurityResultExtIEsIEContainer uses the ProtocolIE-Container shape for object set SecurityResult-ExtIEs of TS 36.413: a list of SecurityResultExtIEsIEField values.
type SecurityResultExtIEsIEContainer []SecurityResultExtIEsIEField

// SensorMeasConfigNameItemExtIEsIEField uses the ProtocolIE-Field shape for object set SensorMeasConfigNameItem-ExtIEs of TS 36.413.
type SensorMeasConfigNameItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.SensorMeasConfigNameItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasConfigNameItemExtIEsIEField) WithoutReplay() SensorMeasConfigNameItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SensorMeasConfigNameItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SensorMeasConfigNameItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SensorMeasConfigNameItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasConfigNameItemExtIEsIEField{}
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
	var zero s06.SensorMeasConfigNameItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeSensorMeasConfigNameItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SensorMeasConfigNameItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set SensorMeasConfigNameItem-ExtIEs of TS 36.413: a list of SensorMeasConfigNameItemExtIEsIEField values.
type SensorMeasConfigNameItemExtIEsIEContainer []SensorMeasConfigNameItemExtIEsIEField

// SensorMeasurementConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set SensorMeasurementConfiguration-ExtIEs of TS 36.413.
type SensorMeasurementConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.SensorMeasurementConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasurementConfigurationExtIEsIEField) WithoutReplay() SensorMeasurementConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SensorMeasurementConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SensorMeasurementConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SensorMeasurementConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SensorMeasurementConfigurationExtIEsIEField{}
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
	var zero s07.SensorMeasurementConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodReason(zero, v.Id), s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeSensorMeasurementConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SensorMeasurementConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set SensorMeasurementConfiguration-ExtIEs of TS 36.413: a list of SensorMeasurementConfigurationExtIEsIEField values.
type SensorMeasurementConfigurationExtIEsIEContainer []SensorMeasurementConfigurationExtIEsIEField

// ServedDCNsItemExtIEsIEField uses the ProtocolIE-Field shape for object set ServedDCNsItem-ExtIEs of TS 36.413.
type ServedDCNsItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.ServedDCNsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedDCNsItemExtIEsIEField) WithoutReplay() ServedDCNsItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ServedDCNsItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ServedDCNsItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeServedDCNsItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeServedDCNsItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ServedDCNsItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedDCNsItemExtIEsIEField{}
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
	var zero s07.ServedDCNsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeServedDCNsItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeServedDCNsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeServedDCNsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ServedDCNsItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set ServedDCNsItem-ExtIEs of TS 36.413: a list of ServedDCNsItemExtIEsIEField values.
type ServedDCNsItemExtIEsIEContainer []ServedDCNsItemExtIEsIEField

// ServedGUMMEIsItemExtIEsIEField uses the ProtocolIE-Field shape for object set ServedGUMMEIsItem-ExtIEs of TS 36.413.
type ServedGUMMEIsItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.ServedGUMMEIsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedGUMMEIsItemExtIEsIEField) WithoutReplay() ServedGUMMEIsItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ServedGUMMEIsItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ServedGUMMEIsItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeServedGUMMEIsItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeServedGUMMEIsItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ServedGUMMEIsItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ServedGUMMEIsItemExtIEsIEField{}
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
	var zero s07.ServedGUMMEIsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeServedGUMMEIsItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeServedGUMMEIsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeServedGUMMEIsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ServedGUMMEIsItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set ServedGUMMEIsItem-ExtIEs of TS 36.413: a list of ServedGUMMEIsItemExtIEsIEField values.
type ServedGUMMEIsItemExtIEsIEContainer []ServedGUMMEIsItemExtIEsIEField

// SourceNgRanNodeIDExtIEsIEField uses the ProtocolIE-Field shape for object set SourceNgRanNode-ID-ExtIEs of TS 36.413.
type SourceNgRanNodeIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.SourceNgRanNodeIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNgRanNodeIDExtIEsIEField) WithoutReplay() SourceNgRanNodeIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SourceNgRanNodeIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SourceNgRanNodeIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSourceNgRanNodeIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSourceNgRanNodeIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SourceNgRanNodeIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNgRanNodeIDExtIEsIEField{}
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
	var zero s07.SourceNgRanNodeIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSourceNgRanNodeIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeSourceNgRanNodeIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeSourceNgRanNodeIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SourceNgRanNodeIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set SourceNgRanNode-ID-ExtIEs of TS 36.413: a list of SourceNgRanNodeIDExtIEsIEField values.
type SourceNgRanNodeIDExtIEsIEContainer []SourceNgRanNodeIDExtIEsIEField

// SourceeNBIDExtIEsIEField uses the ProtocolIE-Field shape for object set SourceeNB-ID-ExtIEs of TS 36.413.
type SourceeNBIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.SourceeNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBIDExtIEsIEField) WithoutReplay() SourceeNBIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SourceeNBIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SourceeNBIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSourceeNBIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSourceeNBIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SourceeNBIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceeNBIDExtIEsIEField{}
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
	var zero s07.SourceeNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSourceeNBIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeSourceeNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeSourceeNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SourceeNBIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set SourceeNB-ID-ExtIEs of TS 36.413: a list of SourceeNBIDExtIEsIEField values.
type SourceeNBIDExtIEsIEContainer []SourceeNBIDExtIEsIEField

// SubscriptionBasedUEDifferentiationInfoExtIEsIEField uses the ProtocolIE-Field shape for object set Subscription-Based-UE-DifferentiationInfo-ExtIEs of TS 36.413.
type SubscriptionBasedUEDifferentiationInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SubscriptionBasedUEDifferentiationInfoExtIEsIEField) WithoutReplay() SubscriptionBasedUEDifferentiationInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SubscriptionBasedUEDifferentiationInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SubscriptionBasedUEDifferentiationInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SubscriptionBasedUEDifferentiationInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SubscriptionBasedUEDifferentiationInfoExtIEsIEField{}
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
	var zero s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodReason(zero, v.Id), s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SubscriptionBasedUEDifferentiationInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set Subscription-Based-UE-DifferentiationInfo-ExtIEs of TS 36.413: a list of SubscriptionBasedUEDifferentiationInfoExtIEsIEField values.
type SubscriptionBasedUEDifferentiationInfoExtIEsIEContainer []SubscriptionBasedUEDifferentiationInfoExtIEsIEField

// SupportedTAsItemExtIEsIEField uses the ProtocolIE-Field shape for object set SupportedTAs-Item-ExtIEs of TS 36.413.
type SupportedTAsItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s08.SupportedTAsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsItemExtIEsIEField) WithoutReplay() SupportedTAsItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SupportedTAsItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SupportedTAsItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s08.BridgeSupportedTAsItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s08.BridgeSupportedTAsItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SupportedTAsItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SupportedTAsItemExtIEsIEField{}
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
	var zero s08.SupportedTAsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s08.BridgeSupportedTAsItemExtIEsValueMethodReason(zero, v.Id), s08.BridgeSupportedTAsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s08.BridgeSupportedTAsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SupportedTAsItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set SupportedTAs-Item-ExtIEs of TS 36.413: a list of SupportedTAsItemExtIEsIEField values.
type SupportedTAsItemExtIEsIEContainer []SupportedTAsItemExtIEsIEField

// SynchronisationInformationExtIEsIEField uses the ProtocolIE-Field shape for object set SynchronisationInformation-ExtIEs of TS 36.413.
type SynchronisationInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.SynchronisationInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SynchronisationInformationExtIEsIEField) WithoutReplay() SynchronisationInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SynchronisationInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SynchronisationInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeSynchronisationInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeSynchronisationInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SynchronisationInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SynchronisationInformationExtIEsIEField{}
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
	var zero s07.SynchronisationInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeSynchronisationInformationExtIEsValueMethodReason(zero, v.Id), s07.BridgeSynchronisationInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeSynchronisationInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SynchronisationInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set SynchronisationInformation-ExtIEs of TS 36.413: a list of SynchronisationInformationExtIEsIEField values.
type SynchronisationInformationExtIEsIEContainer []SynchronisationInformationExtIEsIEField

// TABasedMDTExtIEsIEField uses the ProtocolIE-Field shape for object set TABasedMDT-ExtIEs of TS 36.413.
type TABasedMDTExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TABasedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedMDTExtIEsIEField) WithoutReplay() TABasedMDTExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TABasedMDTExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TABasedMDTExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTABasedMDTExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTABasedMDTExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TABasedMDTExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TABasedMDTExtIEsIEField{}
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
	var zero s07.TABasedMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTABasedMDTExtIEsValueMethodReason(zero, v.Id), s07.BridgeTABasedMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTABasedMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TABasedMDTExtIEsIEContainer uses the ProtocolIE-Container shape for object set TABasedMDT-ExtIEs of TS 36.413: a list of TABasedMDTExtIEsIEField values.
type TABasedMDTExtIEsIEContainer []TABasedMDTExtIEsIEField

// TABasedQMCExtIEsIEField uses the ProtocolIE-Field shape for object set TABasedQMC-ExtIEs of TS 36.413.
type TABasedQMCExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TABasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedQMCExtIEsIEField) WithoutReplay() TABasedQMCExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TABasedQMCExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TABasedQMCExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTABasedQMCExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTABasedQMCExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TABasedQMCExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TABasedQMCExtIEsIEField{}
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
	var zero s07.TABasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTABasedQMCExtIEsValueMethodReason(zero, v.Id), s07.BridgeTABasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTABasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TABasedQMCExtIEsIEContainer uses the ProtocolIE-Container shape for object set TABasedQMC-ExtIEs of TS 36.413: a list of TABasedQMCExtIEsIEField values.
type TABasedQMCExtIEsIEContainer []TABasedQMCExtIEsIEField

// TAIExtIEsIEField uses the ProtocolIE-Field shape for object set TAI-ExtIEs of TS 36.413.
type TAIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TAIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIExtIEsIEField) WithoutReplay() TAIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIExtIEsIEField{}
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
	var zero s07.TAIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTAIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIExtIEsIEContainer uses the ProtocolIE-Container shape for object set TAI-ExtIEs of TS 36.413: a list of TAIExtIEsIEField values.
type TAIExtIEsIEContainer []TAIExtIEsIEField

// TAIBasedMDTExtIEsIEField uses the ProtocolIE-Field shape for object set TAIBasedMDT-ExtIEs of TS 36.413.
type TAIBasedMDTExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TAIBasedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedMDTExtIEsIEField) WithoutReplay() TAIBasedMDTExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIBasedMDTExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIBasedMDTExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIBasedMDTExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIBasedMDTExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIBasedMDTExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedMDTExtIEsIEField{}
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
	var zero s07.TAIBasedMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIBasedMDTExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIBasedMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTAIBasedMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIBasedMDTExtIEsIEContainer uses the ProtocolIE-Container shape for object set TAIBasedMDT-ExtIEs of TS 36.413: a list of TAIBasedMDTExtIEsIEField values.
type TAIBasedMDTExtIEsIEContainer []TAIBasedMDTExtIEsIEField

// TAIBasedQMCExtIEsIEField uses the ProtocolIE-Field shape for object set TAIBasedQMC-ExtIEs of TS 36.413.
type TAIBasedQMCExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TAIBasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedQMCExtIEsIEField) WithoutReplay() TAIBasedQMCExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIBasedQMCExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIBasedQMCExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIBasedQMCExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIBasedQMCExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIBasedQMCExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedQMCExtIEsIEField{}
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
	var zero s07.TAIBasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIBasedQMCExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIBasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTAIBasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIBasedQMCExtIEsIEContainer uses the ProtocolIE-Container shape for object set TAIBasedQMC-ExtIEs of TS 36.413: a list of TAIBasedQMCExtIEsIEField values.
type TAIBasedQMCExtIEsIEContainer []TAIBasedQMCExtIEsIEField

// TAIBroadcastItemExtIEsIEField uses the ProtocolIE-Field shape for object set TAI-Broadcast-Item-ExtIEs of TS 36.413.
type TAIBroadcastItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TAIBroadcastItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBroadcastItemExtIEsIEField) WithoutReplay() TAIBroadcastItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIBroadcastItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIBroadcastItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIBroadcastItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIBroadcastItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIBroadcastItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBroadcastItemExtIEsIEField{}
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
	var zero s07.TAIBroadcastItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIBroadcastItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIBroadcastItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTAIBroadcastItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIBroadcastItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set TAI-Broadcast-Item-ExtIEs of TS 36.413: a list of TAIBroadcastItemExtIEsIEField values.
type TAIBroadcastItemExtIEsIEContainer []TAIBroadcastItemExtIEsIEField

// TAICancelledItemExtIEsIEField uses the ProtocolIE-Field shape for object set TAI-Cancelled-Item-ExtIEs of TS 36.413.
type TAICancelledItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TAICancelledItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAICancelledItemExtIEsIEField) WithoutReplay() TAICancelledItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAICancelledItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAICancelledItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAICancelledItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAICancelledItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAICancelledItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAICancelledItemExtIEsIEField{}
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
	var zero s07.TAICancelledItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAICancelledItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAICancelledItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTAICancelledItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAICancelledItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set TAI-Cancelled-Item-ExtIEs of TS 36.413: a list of TAICancelledItemExtIEsIEField values.
type TAICancelledItemExtIEsIEContainer []TAICancelledItemExtIEsIEField

// TAIItemExtIEsIEField uses the ProtocolIE-Field shape for object set TAIItemExtIEs of TS 36.413.
type TAIItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemExtIEsIEField) WithoutReplay() TAIItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTAIItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTAIItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TAIItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIItemExtIEsIEField{}
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
	var zero s07.TAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTAIItemExtIEsValueMethodReason(zero, v.Id), s07.BridgeTAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TAIItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set TAIItemExtIEs of TS 36.413: a list of TAIItemExtIEsIEField values.
type TAIItemExtIEsIEContainer []TAIItemExtIEsIEField

// TargetNgRanNodeIDExtIEsIEField uses the ProtocolIE-Field shape for object set TargetNgRanNode-ID-ExtIEs of TS 36.413.
type TargetNgRanNodeIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TargetNgRanNodeIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetNgRanNodeIDExtIEsIEField) WithoutReplay() TargetNgRanNodeIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargetNgRanNodeIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargetNgRanNodeIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTargetNgRanNodeIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTargetNgRanNodeIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TargetNgRanNodeIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargetNgRanNodeIDExtIEsIEField{}
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
	var zero s07.TargetNgRanNodeIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTargetNgRanNodeIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeTargetNgRanNodeIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTargetNgRanNodeIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TargetNgRanNodeIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set TargetNgRanNode-ID-ExtIEs of TS 36.413: a list of TargetNgRanNodeIDExtIEsIEField values.
type TargetNgRanNodeIDExtIEsIEContainer []TargetNgRanNodeIDExtIEsIEField

// TargetRNCIDExtIEsIEField uses the ProtocolIE-Field shape for object set TargetRNC-ID-ExtIEs of TS 36.413.
type TargetRNCIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TargetRNCIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetRNCIDExtIEsIEField) WithoutReplay() TargetRNCIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargetRNCIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargetRNCIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTargetRNCIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTargetRNCIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TargetRNCIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargetRNCIDExtIEsIEField{}
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
	var zero s07.TargetRNCIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTargetRNCIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeTargetRNCIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTargetRNCIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TargetRNCIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set TargetRNC-ID-ExtIEs of TS 36.413: a list of TargetRNCIDExtIEsIEField values.
type TargetRNCIDExtIEsIEContainer []TargetRNCIDExtIEsIEField

// TargeteNBIDExtIEsIEField uses the ProtocolIE-Field shape for object set TargeteNB-ID-ExtIEs of TS 36.413.
type TargeteNBIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TargeteNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBIDExtIEsIEField) WithoutReplay() TargeteNBIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargeteNBIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargeteNBIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTargeteNBIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTargeteNBIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TargeteNBIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargeteNBIDExtIEsIEField{}
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
	var zero s07.TargeteNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTargeteNBIDExtIEsValueMethodReason(zero, v.Id), s07.BridgeTargeteNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTargeteNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TargeteNBIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set TargeteNB-ID-ExtIEs of TS 36.413: a list of TargeteNBIDExtIEsIEField values.
type TargeteNBIDExtIEsIEContainer []TargeteNBIDExtIEsIEField

// TimeBasedHandoverInformationExtIEsIEField uses the ProtocolIE-Field shape for object set TimeBasedHandoverInformation-ExtIEs of TS 36.413.
type TimeBasedHandoverInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s07.TimeBasedHandoverInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeBasedHandoverInformationExtIEsIEField) WithoutReplay() TimeBasedHandoverInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TimeBasedHandoverInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TimeBasedHandoverInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TimeBasedHandoverInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TimeBasedHandoverInformationExtIEsIEField{}
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
	var zero s07.TimeBasedHandoverInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodReason(zero, v.Id), s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TimeBasedHandoverInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set TimeBasedHandoverInformation-ExtIEs of TS 36.413: a list of TimeBasedHandoverInformationExtIEsIEField values.
type TimeBasedHandoverInformationExtIEsIEContainer []TimeBasedHandoverInformationExtIEsIEField

// SensorNameConfigExtIEValueERABIEContainerListValueCodec is the concrete ValueCodec[SensorNameConfigExtIEValueERABIEContainerList].
type SensorNameConfigExtIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorNameConfigExtIEValueERABIEContainerList, error)
	encode  func(SensorNameConfigExtIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorNameConfigExtIEValueERABIEContainerList, aper.DecodeState) (SensorNameConfigExtIEValueERABIEContainerList, aper.Snapshot)
	compare func(SensorNameConfigExtIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorNameConfigExtIEValueERABIEContainerListValueCodec) New(value SensorNameConfigExtIEValueERABIEContainerList) (SensorNameConfigExtIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SensorNameConfigExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorNameConfigExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorNameConfigExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorNameConfigExtIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorNameConfigExtIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorNameConfigExtIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorNameConfigExtIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorNameConfigExtIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorNameConfigExtIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorNameConfigExtIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorNameConfigExtIEValueERABIEContainerListValueCodec) EncodeAPER(value SensorNameConfigExtIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorNameConfigExtIEValueERABIEContainerListValueCodec) encodeBudgetValue(value SensorNameConfigExtIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorNameConfigExtIEValueERABIEContainerListValueCodec) encodeChanged(value SensorNameConfigExtIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorNameConfigExtIEValueERABIEContainerList is E-RAB-IE-ContainerList {{SensorNameConfig-ExtIEs}} of TS 36.413: a list of information element fields.
type SensorNameConfigExtIEValueERABIEContainerList []SensorNameConfigExtIEValueProtocolIESingleContainer

// SensorNameConfigExtIEContainer is ProtocolIE-Container {{SensorNameConfig-ExtIEs}} of TS 36.413: a list of SensorNameConfigExtIEField values.
type SensorNameConfigExtIEContainer []SensorNameConfigExtIEField

// SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec is the concrete ValueCodec[SourceNodeIDExtensionIEIEValueERABIEContainerList].
type SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEValueERABIEContainerList, error)
	encode  func(SourceNodeIDExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.DecodeState) (SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.Snapshot)
	compare func(SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) New(value SourceNodeIDExtensionIEIEValueERABIEContainerList) (SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) EncodeAPER(value SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) encodeBudgetValue(value SourceNodeIDExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) encodeChanged(value SourceNodeIDExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDExtensionIEIEValueERABIEContainerList is E-RAB-IE-ContainerList {{SourceNodeID-ExtensionIE}} of TS 36.413: a list of information element fields.
type SourceNodeIDExtensionIEIEValueERABIEContainerList []SourceNodeIDExtensionIEIEValueProtocolIESingleContainer

// SourceNodeIDExtensionIEIEContainer is ProtocolIE-Container {{SourceNodeID-ExtensionIE}} of TS 36.413: a list of SourceNodeIDExtensionIEIEField values.
type SourceNodeIDExtensionIEIEContainer []SourceNodeIDExtensionIEIEField

// RequestedTNLInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[RequestedTNLInfoExtIEsExtField].
type RequestedTNLInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RequestedTNLInfoExtIEsExtField, error)
	encode  func(RequestedTNLInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RequestedTNLInfoExtIEsExtField, aper.DecodeState) (RequestedTNLInfoExtIEsExtField, aper.Snapshot)
	compare func(RequestedTNLInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestedTNLInfoExtIEsExtFieldValueCodec) New(value RequestedTNLInfoExtIEsExtField) (RequestedTNLInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RequestedTNLInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestedTNLInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestedTNLInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestedTNLInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestedTNLInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestedTNLInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestedTNLInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestedTNLInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestedTNLInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestedTNLInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestedTNLInfoExtIEsExtFieldValueCodec) EncodeAPER(value RequestedTNLInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RequestedTNLInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value RequestedTNLInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestedTNLInfoExtIEsExtFieldValueCodec) encodeChanged(value RequestedTNLInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// STMSIExtIEsExtFieldValueCodec is the concrete ValueCodec[STMSIExtIEsExtField].
type STMSIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (STMSIExtIEsExtField, error)
	encode  func(STMSIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(STMSIExtIEsExtField, aper.DecodeState) (STMSIExtIEsExtField, aper.Snapshot)
	compare func(STMSIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c STMSIExtIEsExtFieldValueCodec) New(value STMSIExtIEsExtField) (STMSIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return STMSIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return STMSIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return STMSIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return STMSIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c STMSIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (STMSIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return STMSIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return STMSIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return STMSIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return STMSIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c STMSIExtIEsExtFieldValueCodec) EncodeAPER(value STMSIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c STMSIExtIEsExtFieldValueCodec) encodeBudgetValue(value STMSIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c STMSIExtIEsExtFieldValueCodec) encodeChanged(value STMSIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ScheduledCommunicationTimeExtIEsExtFieldValueCodec is the concrete ValueCodec[ScheduledCommunicationTimeExtIEsExtField].
type ScheduledCommunicationTimeExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtField, error)
	encode  func(ScheduledCommunicationTimeExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ScheduledCommunicationTimeExtIEsExtField, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtField, aper.Snapshot)
	compare func(ScheduledCommunicationTimeExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ScheduledCommunicationTimeExtIEsExtFieldValueCodec) New(value ScheduledCommunicationTimeExtIEsExtField) (ScheduledCommunicationTimeExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ScheduledCommunicationTimeExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ScheduledCommunicationTimeExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ScheduledCommunicationTimeExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ScheduledCommunicationTimeExtIEsExtFieldValueCodec) EncodeAPER(value ScheduledCommunicationTimeExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ScheduledCommunicationTimeExtIEsExtFieldValueCodec) encodeBudgetValue(value ScheduledCommunicationTimeExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ScheduledCommunicationTimeExtIEsExtFieldValueCodec) encodeChanged(value ScheduledCommunicationTimeExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportItemExtIEsExtField].
type SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtField, error)
	encode  func(SecondaryRATDataUsageReportItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItemExtIEsExtField, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtField, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) New(value SecondaryRATDataUsageReportItemExtIEsExtField) (SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) encodeChanged(value SecondaryRATDataUsageReportItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityContextExtIEsExtFieldValueCodec is the concrete ValueCodec[SecurityContextExtIEsExtField].
type SecurityContextExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityContextExtIEsExtField, error)
	encode  func(SecurityContextExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityContextExtIEsExtField, aper.DecodeState) (SecurityContextExtIEsExtField, aper.Snapshot)
	compare func(SecurityContextExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityContextExtIEsExtFieldValueCodec) New(value SecurityContextExtIEsExtField) (SecurityContextExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SecurityContextExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityContextExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityContextExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityContextExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityContextExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityContextExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityContextExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityContextExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityContextExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityContextExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityContextExtIEsExtFieldValueCodec) EncodeAPER(value SecurityContextExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecurityContextExtIEsExtFieldValueCodec) encodeBudgetValue(value SecurityContextExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityContextExtIEsExtFieldValueCodec) encodeChanged(value SecurityContextExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityIndicationExtIEsExtFieldValueCodec is the concrete ValueCodec[SecurityIndicationExtIEsExtField].
type SecurityIndicationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityIndicationExtIEsExtField, error)
	encode  func(SecurityIndicationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityIndicationExtIEsExtField, aper.DecodeState) (SecurityIndicationExtIEsExtField, aper.Snapshot)
	compare func(SecurityIndicationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityIndicationExtIEsExtFieldValueCodec) New(value SecurityIndicationExtIEsExtField) (SecurityIndicationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SecurityIndicationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityIndicationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityIndicationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityIndicationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityIndicationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityIndicationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityIndicationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityIndicationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityIndicationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityIndicationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityIndicationExtIEsExtFieldValueCodec) EncodeAPER(value SecurityIndicationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecurityIndicationExtIEsExtFieldValueCodec) encodeBudgetValue(value SecurityIndicationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityIndicationExtIEsExtFieldValueCodec) encodeChanged(value SecurityIndicationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityResultExtIEsExtFieldValueCodec is the concrete ValueCodec[SecurityResultExtIEsExtField].
type SecurityResultExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityResultExtIEsExtField, error)
	encode  func(SecurityResultExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityResultExtIEsExtField, aper.DecodeState) (SecurityResultExtIEsExtField, aper.Snapshot)
	compare func(SecurityResultExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityResultExtIEsExtFieldValueCodec) New(value SecurityResultExtIEsExtField) (SecurityResultExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SecurityResultExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityResultExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityResultExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityResultExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityResultExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityResultExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityResultExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityResultExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityResultExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityResultExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityResultExtIEsExtFieldValueCodec) EncodeAPER(value SecurityResultExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecurityResultExtIEsExtFieldValueCodec) encodeBudgetValue(value SecurityResultExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityResultExtIEsExtFieldValueCodec) encodeChanged(value SecurityResultExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorMeasConfigNameItemExtIEsExtFieldValueCodec is the concrete ValueCodec[SensorMeasConfigNameItemExtIEsExtField].
type SensorMeasConfigNameItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtField, error)
	encode  func(SensorMeasConfigNameItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorMeasConfigNameItemExtIEsExtField, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtField, aper.Snapshot)
	compare func(SensorMeasConfigNameItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasConfigNameItemExtIEsExtFieldValueCodec) New(value SensorMeasConfigNameItemExtIEsExtField) (SensorMeasConfigNameItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasConfigNameItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasConfigNameItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasConfigNameItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasConfigNameItemExtIEsExtFieldValueCodec) EncodeAPER(value SensorMeasConfigNameItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorMeasConfigNameItemExtIEsExtFieldValueCodec) encodeBudgetValue(value SensorMeasConfigNameItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasConfigNameItemExtIEsExtFieldValueCodec) encodeChanged(value SensorMeasConfigNameItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorMeasurementConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[SensorMeasurementConfigurationExtIEsExtField].
type SensorMeasurementConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtField, error)
	encode  func(SensorMeasurementConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorMeasurementConfigurationExtIEsExtField, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtField, aper.Snapshot)
	compare func(SensorMeasurementConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasurementConfigurationExtIEsExtFieldValueCodec) New(value SensorMeasurementConfigurationExtIEsExtField) (SensorMeasurementConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasurementConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasurementConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasurementConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasurementConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value SensorMeasurementConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorMeasurementConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value SensorMeasurementConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasurementConfigurationExtIEsExtFieldValueCodec) encodeChanged(value SensorMeasurementConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedDCNsItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ServedDCNsItemExtIEsExtField].
type ServedDCNsItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedDCNsItemExtIEsExtField, error)
	encode  func(ServedDCNsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedDCNsItemExtIEsExtField, aper.DecodeState) (ServedDCNsItemExtIEsExtField, aper.Snapshot)
	compare func(ServedDCNsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedDCNsItemExtIEsExtFieldValueCodec) New(value ServedDCNsItemExtIEsExtField) (ServedDCNsItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ServedDCNsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedDCNsItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedDCNsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedDCNsItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedDCNsItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedDCNsItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedDCNsItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedDCNsItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedDCNsItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedDCNsItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedDCNsItemExtIEsExtFieldValueCodec) EncodeAPER(value ServedDCNsItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ServedDCNsItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ServedDCNsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedDCNsItemExtIEsExtFieldValueCodec) encodeChanged(value ServedDCNsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedGUMMEIsItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ServedGUMMEIsItemExtIEsExtField].
type ServedGUMMEIsItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtField, error)
	encode  func(ServedGUMMEIsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedGUMMEIsItemExtIEsExtField, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtField, aper.Snapshot)
	compare func(ServedGUMMEIsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedGUMMEIsItemExtIEsExtFieldValueCodec) New(value ServedGUMMEIsItemExtIEsExtField) (ServedGUMMEIsItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ServedGUMMEIsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedGUMMEIsItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedGUMMEIsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedGUMMEIsItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedGUMMEIsItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedGUMMEIsItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedGUMMEIsItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedGUMMEIsItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedGUMMEIsItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedGUMMEIsItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedGUMMEIsItemExtIEsExtFieldValueCodec) EncodeAPER(value ServedGUMMEIsItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ServedGUMMEIsItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ServedGUMMEIsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedGUMMEIsItemExtIEsExtFieldValueCodec) encodeChanged(value ServedGUMMEIsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNgRanNodeIDExtIEsExtFieldValueCodec is the concrete ValueCodec[SourceNgRanNodeIDExtIEsExtField].
type SourceNgRanNodeIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtField, error)
	encode  func(SourceNgRanNodeIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNgRanNodeIDExtIEsExtField, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtField, aper.Snapshot)
	compare func(SourceNgRanNodeIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNgRanNodeIDExtIEsExtFieldValueCodec) New(value SourceNgRanNodeIDExtIEsExtField) (SourceNgRanNodeIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SourceNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNgRanNodeIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNgRanNodeIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNgRanNodeIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNgRanNodeIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNgRanNodeIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNgRanNodeIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNgRanNodeIDExtIEsExtFieldValueCodec) EncodeAPER(value SourceNgRanNodeIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNgRanNodeIDExtIEsExtFieldValueCodec) encodeBudgetValue(value SourceNgRanNodeIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNgRanNodeIDExtIEsExtFieldValueCodec) encodeChanged(value SourceNgRanNodeIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceeNBIDExtIEsExtFieldValueCodec is the concrete ValueCodec[SourceeNBIDExtIEsExtField].
type SourceeNBIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceeNBIDExtIEsExtField, error)
	encode  func(SourceeNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceeNBIDExtIEsExtField, aper.DecodeState) (SourceeNBIDExtIEsExtField, aper.Snapshot)
	compare func(SourceeNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceeNBIDExtIEsExtFieldValueCodec) New(value SourceeNBIDExtIEsExtField) (SourceeNBIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SourceeNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceeNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceeNBIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceeNBIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceeNBIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceeNBIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceeNBIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceeNBIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceeNBIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceeNBIDExtIEsExtFieldValueCodec) EncodeAPER(value SourceeNBIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceeNBIDExtIEsExtFieldValueCodec) encodeBudgetValue(value SourceeNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceeNBIDExtIEsExtFieldValueCodec) encodeChanged(value SourceeNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[SubscriptionBasedUEDifferentiationInfoExtIEsExtField].
type SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtField, error)
	encode  func(SubscriptionBasedUEDifferentiationInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.Snapshot)
	compare func(SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) New(value SubscriptionBasedUEDifferentiationInfoExtIEsExtField) (SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) EncodeAPER(value SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value SubscriptionBasedUEDifferentiationInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) encodeChanged(value SubscriptionBasedUEDifferentiationInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SupportedTAsItemExtIEsExtFieldValueCodec is the concrete ValueCodec[SupportedTAsItemExtIEsExtField].
type SupportedTAsItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SupportedTAsItemExtIEsExtField, error)
	encode  func(SupportedTAsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SupportedTAsItemExtIEsExtField, aper.DecodeState) (SupportedTAsItemExtIEsExtField, aper.Snapshot)
	compare func(SupportedTAsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SupportedTAsItemExtIEsExtFieldValueCodec) New(value SupportedTAsItemExtIEsExtField) (SupportedTAsItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SupportedTAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SupportedTAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SupportedTAsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SupportedTAsItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SupportedTAsItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SupportedTAsItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SupportedTAsItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SupportedTAsItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SupportedTAsItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SupportedTAsItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SupportedTAsItemExtIEsExtFieldValueCodec) EncodeAPER(value SupportedTAsItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SupportedTAsItemExtIEsExtFieldValueCodec) encodeBudgetValue(value SupportedTAsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SupportedTAsItemExtIEsExtFieldValueCodec) encodeChanged(value SupportedTAsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SynchronisationInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[SynchronisationInformationExtIEsExtField].
type SynchronisationInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SynchronisationInformationExtIEsExtField, error)
	encode  func(SynchronisationInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SynchronisationInformationExtIEsExtField, aper.DecodeState) (SynchronisationInformationExtIEsExtField, aper.Snapshot)
	compare func(SynchronisationInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SynchronisationInformationExtIEsExtFieldValueCodec) New(value SynchronisationInformationExtIEsExtField) (SynchronisationInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SynchronisationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SynchronisationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SynchronisationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SynchronisationInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SynchronisationInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SynchronisationInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SynchronisationInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SynchronisationInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SynchronisationInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SynchronisationInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SynchronisationInformationExtIEsExtFieldValueCodec) EncodeAPER(value SynchronisationInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SynchronisationInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value SynchronisationInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SynchronisationInformationExtIEsExtFieldValueCodec) encodeChanged(value SynchronisationInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TABasedMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[TABasedMDTExtIEsExtField].
type TABasedMDTExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TABasedMDTExtIEsExtField, error)
	encode  func(TABasedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TABasedMDTExtIEsExtField, aper.DecodeState) (TABasedMDTExtIEsExtField, aper.Snapshot)
	compare func(TABasedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TABasedMDTExtIEsExtFieldValueCodec) New(value TABasedMDTExtIEsExtField) (TABasedMDTExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TABasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TABasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TABasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TABasedMDTExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TABasedMDTExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TABasedMDTExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TABasedMDTExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TABasedMDTExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TABasedMDTExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TABasedMDTExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TABasedMDTExtIEsExtFieldValueCodec) EncodeAPER(value TABasedMDTExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TABasedMDTExtIEsExtFieldValueCodec) encodeBudgetValue(value TABasedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TABasedMDTExtIEsExtFieldValueCodec) encodeChanged(value TABasedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TABasedQMCExtIEsExtFieldValueCodec is the concrete ValueCodec[TABasedQMCExtIEsExtField].
type TABasedQMCExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TABasedQMCExtIEsExtField, error)
	encode  func(TABasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TABasedQMCExtIEsExtField, aper.DecodeState) (TABasedQMCExtIEsExtField, aper.Snapshot)
	compare func(TABasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TABasedQMCExtIEsExtFieldValueCodec) New(value TABasedQMCExtIEsExtField) (TABasedQMCExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TABasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TABasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TABasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TABasedQMCExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TABasedQMCExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TABasedQMCExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TABasedQMCExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TABasedQMCExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TABasedQMCExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TABasedQMCExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TABasedQMCExtIEsExtFieldValueCodec) EncodeAPER(value TABasedQMCExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TABasedQMCExtIEsExtFieldValueCodec) encodeBudgetValue(value TABasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TABasedQMCExtIEsExtFieldValueCodec) encodeChanged(value TABasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBasedMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[TAIBasedMDTExtIEsExtField].
type TAIBasedMDTExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedMDTExtIEsExtField, error)
	encode  func(TAIBasedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedMDTExtIEsExtField, aper.DecodeState) (TAIBasedMDTExtIEsExtField, aper.Snapshot)
	compare func(TAIBasedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedMDTExtIEsExtFieldValueCodec) New(value TAIBasedMDTExtIEsExtField) (TAIBasedMDTExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TAIBasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedMDTExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedMDTExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedMDTExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedMDTExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedMDTExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedMDTExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedMDTExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedMDTExtIEsExtFieldValueCodec) EncodeAPER(value TAIBasedMDTExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedMDTExtIEsExtFieldValueCodec) encodeBudgetValue(value TAIBasedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedMDTExtIEsExtFieldValueCodec) encodeChanged(value TAIBasedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBasedQMCExtIEsExtFieldValueCodec is the concrete ValueCodec[TAIBasedQMCExtIEsExtField].
type TAIBasedQMCExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedQMCExtIEsExtField, error)
	encode  func(TAIBasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedQMCExtIEsExtField, aper.DecodeState) (TAIBasedQMCExtIEsExtField, aper.Snapshot)
	compare func(TAIBasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedQMCExtIEsExtFieldValueCodec) New(value TAIBasedQMCExtIEsExtField) (TAIBasedQMCExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TAIBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedQMCExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedQMCExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedQMCExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedQMCExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedQMCExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedQMCExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedQMCExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedQMCExtIEsExtFieldValueCodec) EncodeAPER(value TAIBasedQMCExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedQMCExtIEsExtFieldValueCodec) encodeBudgetValue(value TAIBasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedQMCExtIEsExtFieldValueCodec) encodeChanged(value TAIBasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBroadcastItemExtIEsExtFieldValueCodec is the concrete ValueCodec[TAIBroadcastItemExtIEsExtField].
type TAIBroadcastItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBroadcastItemExtIEsExtField, error)
	encode  func(TAIBroadcastItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBroadcastItemExtIEsExtField, aper.DecodeState) (TAIBroadcastItemExtIEsExtField, aper.Snapshot)
	compare func(TAIBroadcastItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBroadcastItemExtIEsExtFieldValueCodec) New(value TAIBroadcastItemExtIEsExtField) (TAIBroadcastItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TAIBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBroadcastItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBroadcastItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBroadcastItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBroadcastItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBroadcastItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBroadcastItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBroadcastItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBroadcastItemExtIEsExtFieldValueCodec) EncodeAPER(value TAIBroadcastItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBroadcastItemExtIEsExtFieldValueCodec) encodeBudgetValue(value TAIBroadcastItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBroadcastItemExtIEsExtFieldValueCodec) encodeChanged(value TAIBroadcastItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAICancelledItemExtIEsExtFieldValueCodec is the concrete ValueCodec[TAICancelledItemExtIEsExtField].
type TAICancelledItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAICancelledItemExtIEsExtField, error)
	encode  func(TAICancelledItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAICancelledItemExtIEsExtField, aper.DecodeState) (TAICancelledItemExtIEsExtField, aper.Snapshot)
	compare func(TAICancelledItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAICancelledItemExtIEsExtFieldValueCodec) New(value TAICancelledItemExtIEsExtField) (TAICancelledItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TAICancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAICancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAICancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAICancelledItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAICancelledItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAICancelledItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAICancelledItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAICancelledItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAICancelledItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAICancelledItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAICancelledItemExtIEsExtFieldValueCodec) EncodeAPER(value TAICancelledItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAICancelledItemExtIEsExtFieldValueCodec) encodeBudgetValue(value TAICancelledItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAICancelledItemExtIEsExtFieldValueCodec) encodeChanged(value TAICancelledItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIExtIEsExtFieldValueCodec is the concrete ValueCodec[TAIExtIEsExtField].
type TAIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIExtIEsExtField, error)
	encode  func(TAIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIExtIEsExtField, aper.DecodeState) (TAIExtIEsExtField, aper.Snapshot)
	compare func(TAIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIExtIEsExtFieldValueCodec) New(value TAIExtIEsExtField) (TAIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TAIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIExtIEsExtFieldValueCodec) EncodeAPER(value TAIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIExtIEsExtFieldValueCodec) encodeBudgetValue(value TAIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIExtIEsExtFieldValueCodec) encodeChanged(value TAIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemExtIEsExtFieldValueCodec is the concrete ValueCodec[TAIItemExtIEsExtField].
type TAIItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItemExtIEsExtField, error)
	encode  func(TAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItemExtIEsExtField, aper.DecodeState) (TAIItemExtIEsExtField, aper.Snapshot)
	compare func(TAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemExtIEsExtFieldValueCodec) New(value TAIItemExtIEsExtField) (TAIItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemExtIEsExtFieldValueCodec) EncodeAPER(value TAIItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIItemExtIEsExtFieldValueCodec) encodeBudgetValue(value TAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemExtIEsExtFieldValueCodec) encodeChanged(value TAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetNgRanNodeIDExtIEsExtFieldValueCodec is the concrete ValueCodec[TargetNgRanNodeIDExtIEsExtField].
type TargetNgRanNodeIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtField, error)
	encode  func(TargetNgRanNodeIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargetNgRanNodeIDExtIEsExtField, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtField, aper.Snapshot)
	compare func(TargetNgRanNodeIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetNgRanNodeIDExtIEsExtFieldValueCodec) New(value TargetNgRanNodeIDExtIEsExtField) (TargetNgRanNodeIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TargetNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetNgRanNodeIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetNgRanNodeIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetNgRanNodeIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetNgRanNodeIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetNgRanNodeIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetNgRanNodeIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetNgRanNodeIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetNgRanNodeIDExtIEsExtFieldValueCodec) EncodeAPER(value TargetNgRanNodeIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargetNgRanNodeIDExtIEsExtFieldValueCodec) encodeBudgetValue(value TargetNgRanNodeIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetNgRanNodeIDExtIEsExtFieldValueCodec) encodeChanged(value TargetNgRanNodeIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetRNCIDExtIEsExtFieldValueCodec is the concrete ValueCodec[TargetRNCIDExtIEsExtField].
type TargetRNCIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargetRNCIDExtIEsExtField, error)
	encode  func(TargetRNCIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargetRNCIDExtIEsExtField, aper.DecodeState) (TargetRNCIDExtIEsExtField, aper.Snapshot)
	compare func(TargetRNCIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetRNCIDExtIEsExtFieldValueCodec) New(value TargetRNCIDExtIEsExtField) (TargetRNCIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TargetRNCIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetRNCIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetRNCIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetRNCIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetRNCIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetRNCIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetRNCIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetRNCIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetRNCIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetRNCIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetRNCIDExtIEsExtFieldValueCodec) EncodeAPER(value TargetRNCIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargetRNCIDExtIEsExtFieldValueCodec) encodeBudgetValue(value TargetRNCIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetRNCIDExtIEsExtFieldValueCodec) encodeChanged(value TargetRNCIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargeteNBIDExtIEsExtFieldValueCodec is the concrete ValueCodec[TargeteNBIDExtIEsExtField].
type TargeteNBIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargeteNBIDExtIEsExtField, error)
	encode  func(TargeteNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargeteNBIDExtIEsExtField, aper.DecodeState) (TargeteNBIDExtIEsExtField, aper.Snapshot)
	compare func(TargeteNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargeteNBIDExtIEsExtFieldValueCodec) New(value TargeteNBIDExtIEsExtField) (TargeteNBIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TargeteNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargeteNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargeteNBIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargeteNBIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargeteNBIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargeteNBIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargeteNBIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargeteNBIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargeteNBIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargeteNBIDExtIEsExtFieldValueCodec) EncodeAPER(value TargeteNBIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargeteNBIDExtIEsExtFieldValueCodec) encodeBudgetValue(value TargeteNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargeteNBIDExtIEsExtFieldValueCodec) encodeChanged(value TargeteNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeBasedHandoverInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[TimeBasedHandoverInformationExtIEsExtField].
type TimeBasedHandoverInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtField, error)
	encode  func(TimeBasedHandoverInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TimeBasedHandoverInformationExtIEsExtField, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtField, aper.Snapshot)
	compare func(TimeBasedHandoverInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeBasedHandoverInformationExtIEsExtFieldValueCodec) New(value TimeBasedHandoverInformationExtIEsExtField) (TimeBasedHandoverInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeBasedHandoverInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeBasedHandoverInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeBasedHandoverInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeBasedHandoverInformationExtIEsExtFieldValueCodec) EncodeAPER(value TimeBasedHandoverInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeBasedHandoverInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value TimeBasedHandoverInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeBasedHandoverInformationExtIEsExtFieldValueCodec) encodeChanged(value TimeBasedHandoverInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RequestedTNLInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[RequestedTNLInfoExtIEsExtContainer].
type RequestedTNLInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RequestedTNLInfoExtIEsExtContainer, error)
	encode  func(RequestedTNLInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RequestedTNLInfoExtIEsExtContainer, aper.DecodeState) (RequestedTNLInfoExtIEsExtContainer, aper.Snapshot)
	compare func(RequestedTNLInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestedTNLInfoExtIEsExtContainerValueCodec) New(value RequestedTNLInfoExtIEsExtContainer) (RequestedTNLInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RequestedTNLInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestedTNLInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestedTNLInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestedTNLInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestedTNLInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestedTNLInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestedTNLInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestedTNLInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestedTNLInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestedTNLInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestedTNLInfoExtIEsExtContainerValueCodec) EncodeAPER(value RequestedTNLInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RequestedTNLInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value RequestedTNLInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestedTNLInfoExtIEsExtContainerValueCodec) encodeChanged(value RequestedTNLInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// STMSIExtIEsExtContainerValueCodec is the concrete ValueCodec[STMSIExtIEsExtContainer].
type STMSIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (STMSIExtIEsExtContainer, error)
	encode  func(STMSIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(STMSIExtIEsExtContainer, aper.DecodeState) (STMSIExtIEsExtContainer, aper.Snapshot)
	compare func(STMSIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c STMSIExtIEsExtContainerValueCodec) New(value STMSIExtIEsExtContainer) (STMSIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return STMSIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return STMSIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return STMSIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return STMSIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c STMSIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (STMSIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return STMSIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return STMSIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return STMSIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return STMSIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c STMSIExtIEsExtContainerValueCodec) EncodeAPER(value STMSIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c STMSIExtIEsExtContainerValueCodec) encodeBudgetValue(value STMSIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c STMSIExtIEsExtContainerValueCodec) encodeChanged(value STMSIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ScheduledCommunicationTimeExtIEsExtContainerValueCodec is the concrete ValueCodec[ScheduledCommunicationTimeExtIEsExtContainer].
type ScheduledCommunicationTimeExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtContainer, error)
	encode  func(ScheduledCommunicationTimeExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ScheduledCommunicationTimeExtIEsExtContainer, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtContainer, aper.Snapshot)
	compare func(ScheduledCommunicationTimeExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ScheduledCommunicationTimeExtIEsExtContainerValueCodec) New(value ScheduledCommunicationTimeExtIEsExtContainer) (ScheduledCommunicationTimeExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ScheduledCommunicationTimeExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ScheduledCommunicationTimeExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ScheduledCommunicationTimeExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ScheduledCommunicationTimeExtIEsExtContainerValueCodec) EncodeAPER(value ScheduledCommunicationTimeExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ScheduledCommunicationTimeExtIEsExtContainerValueCodec) encodeBudgetValue(value ScheduledCommunicationTimeExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ScheduledCommunicationTimeExtIEsExtContainerValueCodec) encodeChanged(value ScheduledCommunicationTimeExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportItemExtIEsExtContainer].
type SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtContainer, error)
	encode  func(SecondaryRATDataUsageReportItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItemExtIEsExtContainer, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtContainer, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) New(value SecondaryRATDataUsageReportItemExtIEsExtContainer) (SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) encodeChanged(value SecondaryRATDataUsageReportItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityContextExtIEsExtContainerValueCodec is the concrete ValueCodec[SecurityContextExtIEsExtContainer].
type SecurityContextExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityContextExtIEsExtContainer, error)
	encode  func(SecurityContextExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityContextExtIEsExtContainer, aper.DecodeState) (SecurityContextExtIEsExtContainer, aper.Snapshot)
	compare func(SecurityContextExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityContextExtIEsExtContainerValueCodec) New(value SecurityContextExtIEsExtContainer) (SecurityContextExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SecurityContextExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityContextExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityContextExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityContextExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityContextExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityContextExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityContextExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityContextExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityContextExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityContextExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityContextExtIEsExtContainerValueCodec) EncodeAPER(value SecurityContextExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecurityContextExtIEsExtContainerValueCodec) encodeBudgetValue(value SecurityContextExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityContextExtIEsExtContainerValueCodec) encodeChanged(value SecurityContextExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityIndicationExtIEsExtContainerValueCodec is the concrete ValueCodec[SecurityIndicationExtIEsExtContainer].
type SecurityIndicationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityIndicationExtIEsExtContainer, error)
	encode  func(SecurityIndicationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityIndicationExtIEsExtContainer, aper.DecodeState) (SecurityIndicationExtIEsExtContainer, aper.Snapshot)
	compare func(SecurityIndicationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityIndicationExtIEsExtContainerValueCodec) New(value SecurityIndicationExtIEsExtContainer) (SecurityIndicationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SecurityIndicationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityIndicationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityIndicationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityIndicationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityIndicationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityIndicationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityIndicationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityIndicationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityIndicationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityIndicationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityIndicationExtIEsExtContainerValueCodec) EncodeAPER(value SecurityIndicationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecurityIndicationExtIEsExtContainerValueCodec) encodeBudgetValue(value SecurityIndicationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityIndicationExtIEsExtContainerValueCodec) encodeChanged(value SecurityIndicationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityResultExtIEsExtContainerValueCodec is the concrete ValueCodec[SecurityResultExtIEsExtContainer].
type SecurityResultExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityResultExtIEsExtContainer, error)
	encode  func(SecurityResultExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityResultExtIEsExtContainer, aper.DecodeState) (SecurityResultExtIEsExtContainer, aper.Snapshot)
	compare func(SecurityResultExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityResultExtIEsExtContainerValueCodec) New(value SecurityResultExtIEsExtContainer) (SecurityResultExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SecurityResultExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityResultExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityResultExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityResultExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityResultExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityResultExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityResultExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityResultExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityResultExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityResultExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityResultExtIEsExtContainerValueCodec) EncodeAPER(value SecurityResultExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecurityResultExtIEsExtContainerValueCodec) encodeBudgetValue(value SecurityResultExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityResultExtIEsExtContainerValueCodec) encodeChanged(value SecurityResultExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorMeasConfigNameItemExtIEsExtContainerValueCodec is the concrete ValueCodec[SensorMeasConfigNameItemExtIEsExtContainer].
type SensorMeasConfigNameItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtContainer, error)
	encode  func(SensorMeasConfigNameItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorMeasConfigNameItemExtIEsExtContainer, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtContainer, aper.Snapshot)
	compare func(SensorMeasConfigNameItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasConfigNameItemExtIEsExtContainerValueCodec) New(value SensorMeasConfigNameItemExtIEsExtContainer) (SensorMeasConfigNameItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasConfigNameItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasConfigNameItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasConfigNameItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasConfigNameItemExtIEsExtContainerValueCodec) EncodeAPER(value SensorMeasConfigNameItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorMeasConfigNameItemExtIEsExtContainerValueCodec) encodeBudgetValue(value SensorMeasConfigNameItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasConfigNameItemExtIEsExtContainerValueCodec) encodeChanged(value SensorMeasConfigNameItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorMeasurementConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[SensorMeasurementConfigurationExtIEsExtContainer].
type SensorMeasurementConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtContainer, error)
	encode  func(SensorMeasurementConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorMeasurementConfigurationExtIEsExtContainer, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(SensorMeasurementConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasurementConfigurationExtIEsExtContainerValueCodec) New(value SensorMeasurementConfigurationExtIEsExtContainer) (SensorMeasurementConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasurementConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasurementConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasurementConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasurementConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value SensorMeasurementConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorMeasurementConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value SensorMeasurementConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasurementConfigurationExtIEsExtContainerValueCodec) encodeChanged(value SensorMeasurementConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedDCNsItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ServedDCNsItemExtIEsExtContainer].
type ServedDCNsItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedDCNsItemExtIEsExtContainer, error)
	encode  func(ServedDCNsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedDCNsItemExtIEsExtContainer, aper.DecodeState) (ServedDCNsItemExtIEsExtContainer, aper.Snapshot)
	compare func(ServedDCNsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedDCNsItemExtIEsExtContainerValueCodec) New(value ServedDCNsItemExtIEsExtContainer) (ServedDCNsItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ServedDCNsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedDCNsItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedDCNsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedDCNsItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedDCNsItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedDCNsItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedDCNsItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedDCNsItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedDCNsItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedDCNsItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedDCNsItemExtIEsExtContainerValueCodec) EncodeAPER(value ServedDCNsItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ServedDCNsItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ServedDCNsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedDCNsItemExtIEsExtContainerValueCodec) encodeChanged(value ServedDCNsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedGUMMEIsItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ServedGUMMEIsItemExtIEsExtContainer].
type ServedGUMMEIsItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtContainer, error)
	encode  func(ServedGUMMEIsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ServedGUMMEIsItemExtIEsExtContainer, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtContainer, aper.Snapshot)
	compare func(ServedGUMMEIsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedGUMMEIsItemExtIEsExtContainerValueCodec) New(value ServedGUMMEIsItemExtIEsExtContainer) (ServedGUMMEIsItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ServedGUMMEIsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedGUMMEIsItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedGUMMEIsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedGUMMEIsItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedGUMMEIsItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedGUMMEIsItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedGUMMEIsItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedGUMMEIsItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedGUMMEIsItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedGUMMEIsItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedGUMMEIsItemExtIEsExtContainerValueCodec) EncodeAPER(value ServedGUMMEIsItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ServedGUMMEIsItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ServedGUMMEIsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedGUMMEIsItemExtIEsExtContainerValueCodec) encodeChanged(value ServedGUMMEIsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNgRanNodeIDExtIEsExtContainerValueCodec is the concrete ValueCodec[SourceNgRanNodeIDExtIEsExtContainer].
type SourceNgRanNodeIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtContainer, error)
	encode  func(SourceNgRanNodeIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNgRanNodeIDExtIEsExtContainer, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtContainer, aper.Snapshot)
	compare func(SourceNgRanNodeIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNgRanNodeIDExtIEsExtContainerValueCodec) New(value SourceNgRanNodeIDExtIEsExtContainer) (SourceNgRanNodeIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SourceNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNgRanNodeIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNgRanNodeIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNgRanNodeIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNgRanNodeIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNgRanNodeIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNgRanNodeIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNgRanNodeIDExtIEsExtContainerValueCodec) EncodeAPER(value SourceNgRanNodeIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNgRanNodeIDExtIEsExtContainerValueCodec) encodeBudgetValue(value SourceNgRanNodeIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNgRanNodeIDExtIEsExtContainerValueCodec) encodeChanged(value SourceNgRanNodeIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceeNBIDExtIEsExtContainerValueCodec is the concrete ValueCodec[SourceeNBIDExtIEsExtContainer].
type SourceeNBIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceeNBIDExtIEsExtContainer, error)
	encode  func(SourceeNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceeNBIDExtIEsExtContainer, aper.DecodeState) (SourceeNBIDExtIEsExtContainer, aper.Snapshot)
	compare func(SourceeNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceeNBIDExtIEsExtContainerValueCodec) New(value SourceeNBIDExtIEsExtContainer) (SourceeNBIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SourceeNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceeNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceeNBIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceeNBIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceeNBIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceeNBIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceeNBIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceeNBIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceeNBIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceeNBIDExtIEsExtContainerValueCodec) EncodeAPER(value SourceeNBIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceeNBIDExtIEsExtContainerValueCodec) encodeBudgetValue(value SourceeNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceeNBIDExtIEsExtContainerValueCodec) encodeChanged(value SourceeNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer].
type SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, error)
	encode  func(SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.Snapshot)
	compare func(SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) New(value SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer) (SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) EncodeAPER(value SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) encodeChanged(value SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SupportedTAsItemExtIEsExtContainerValueCodec is the concrete ValueCodec[SupportedTAsItemExtIEsExtContainer].
type SupportedTAsItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SupportedTAsItemExtIEsExtContainer, error)
	encode  func(SupportedTAsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SupportedTAsItemExtIEsExtContainer, aper.DecodeState) (SupportedTAsItemExtIEsExtContainer, aper.Snapshot)
	compare func(SupportedTAsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SupportedTAsItemExtIEsExtContainerValueCodec) New(value SupportedTAsItemExtIEsExtContainer) (SupportedTAsItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SupportedTAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SupportedTAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SupportedTAsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SupportedTAsItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SupportedTAsItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SupportedTAsItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SupportedTAsItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SupportedTAsItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SupportedTAsItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SupportedTAsItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SupportedTAsItemExtIEsExtContainerValueCodec) EncodeAPER(value SupportedTAsItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SupportedTAsItemExtIEsExtContainerValueCodec) encodeBudgetValue(value SupportedTAsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SupportedTAsItemExtIEsExtContainerValueCodec) encodeChanged(value SupportedTAsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SynchronisationInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[SynchronisationInformationExtIEsExtContainer].
type SynchronisationInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SynchronisationInformationExtIEsExtContainer, error)
	encode  func(SynchronisationInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SynchronisationInformationExtIEsExtContainer, aper.DecodeState) (SynchronisationInformationExtIEsExtContainer, aper.Snapshot)
	compare func(SynchronisationInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SynchronisationInformationExtIEsExtContainerValueCodec) New(value SynchronisationInformationExtIEsExtContainer) (SynchronisationInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SynchronisationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SynchronisationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SynchronisationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SynchronisationInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SynchronisationInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SynchronisationInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SynchronisationInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SynchronisationInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SynchronisationInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SynchronisationInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SynchronisationInformationExtIEsExtContainerValueCodec) EncodeAPER(value SynchronisationInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SynchronisationInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value SynchronisationInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SynchronisationInformationExtIEsExtContainerValueCodec) encodeChanged(value SynchronisationInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TABasedMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[TABasedMDTExtIEsExtContainer].
type TABasedMDTExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TABasedMDTExtIEsExtContainer, error)
	encode  func(TABasedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TABasedMDTExtIEsExtContainer, aper.DecodeState) (TABasedMDTExtIEsExtContainer, aper.Snapshot)
	compare func(TABasedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TABasedMDTExtIEsExtContainerValueCodec) New(value TABasedMDTExtIEsExtContainer) (TABasedMDTExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TABasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TABasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TABasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TABasedMDTExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TABasedMDTExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TABasedMDTExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TABasedMDTExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TABasedMDTExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TABasedMDTExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TABasedMDTExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TABasedMDTExtIEsExtContainerValueCodec) EncodeAPER(value TABasedMDTExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TABasedMDTExtIEsExtContainerValueCodec) encodeBudgetValue(value TABasedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TABasedMDTExtIEsExtContainerValueCodec) encodeChanged(value TABasedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TABasedQMCExtIEsExtContainerValueCodec is the concrete ValueCodec[TABasedQMCExtIEsExtContainer].
type TABasedQMCExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TABasedQMCExtIEsExtContainer, error)
	encode  func(TABasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TABasedQMCExtIEsExtContainer, aper.DecodeState) (TABasedQMCExtIEsExtContainer, aper.Snapshot)
	compare func(TABasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TABasedQMCExtIEsExtContainerValueCodec) New(value TABasedQMCExtIEsExtContainer) (TABasedQMCExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TABasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TABasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TABasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TABasedQMCExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TABasedQMCExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TABasedQMCExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TABasedQMCExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TABasedQMCExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TABasedQMCExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TABasedQMCExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TABasedQMCExtIEsExtContainerValueCodec) EncodeAPER(value TABasedQMCExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TABasedQMCExtIEsExtContainerValueCodec) encodeBudgetValue(value TABasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TABasedQMCExtIEsExtContainerValueCodec) encodeChanged(value TABasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBasedMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[TAIBasedMDTExtIEsExtContainer].
type TAIBasedMDTExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedMDTExtIEsExtContainer, error)
	encode  func(TAIBasedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedMDTExtIEsExtContainer, aper.DecodeState) (TAIBasedMDTExtIEsExtContainer, aper.Snapshot)
	compare func(TAIBasedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedMDTExtIEsExtContainerValueCodec) New(value TAIBasedMDTExtIEsExtContainer) (TAIBasedMDTExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TAIBasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedMDTExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedMDTExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedMDTExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedMDTExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedMDTExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedMDTExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedMDTExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedMDTExtIEsExtContainerValueCodec) EncodeAPER(value TAIBasedMDTExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedMDTExtIEsExtContainerValueCodec) encodeBudgetValue(value TAIBasedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedMDTExtIEsExtContainerValueCodec) encodeChanged(value TAIBasedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBasedQMCExtIEsExtContainerValueCodec is the concrete ValueCodec[TAIBasedQMCExtIEsExtContainer].
type TAIBasedQMCExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedQMCExtIEsExtContainer, error)
	encode  func(TAIBasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedQMCExtIEsExtContainer, aper.DecodeState) (TAIBasedQMCExtIEsExtContainer, aper.Snapshot)
	compare func(TAIBasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedQMCExtIEsExtContainerValueCodec) New(value TAIBasedQMCExtIEsExtContainer) (TAIBasedQMCExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TAIBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedQMCExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedQMCExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedQMCExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedQMCExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedQMCExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedQMCExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedQMCExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedQMCExtIEsExtContainerValueCodec) EncodeAPER(value TAIBasedQMCExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedQMCExtIEsExtContainerValueCodec) encodeBudgetValue(value TAIBasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedQMCExtIEsExtContainerValueCodec) encodeChanged(value TAIBasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBroadcastItemExtIEsExtContainerValueCodec is the concrete ValueCodec[TAIBroadcastItemExtIEsExtContainer].
type TAIBroadcastItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBroadcastItemExtIEsExtContainer, error)
	encode  func(TAIBroadcastItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBroadcastItemExtIEsExtContainer, aper.DecodeState) (TAIBroadcastItemExtIEsExtContainer, aper.Snapshot)
	compare func(TAIBroadcastItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBroadcastItemExtIEsExtContainerValueCodec) New(value TAIBroadcastItemExtIEsExtContainer) (TAIBroadcastItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TAIBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBroadcastItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBroadcastItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBroadcastItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBroadcastItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBroadcastItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBroadcastItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBroadcastItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBroadcastItemExtIEsExtContainerValueCodec) EncodeAPER(value TAIBroadcastItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBroadcastItemExtIEsExtContainerValueCodec) encodeBudgetValue(value TAIBroadcastItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBroadcastItemExtIEsExtContainerValueCodec) encodeChanged(value TAIBroadcastItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAICancelledItemExtIEsExtContainerValueCodec is the concrete ValueCodec[TAICancelledItemExtIEsExtContainer].
type TAICancelledItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAICancelledItemExtIEsExtContainer, error)
	encode  func(TAICancelledItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAICancelledItemExtIEsExtContainer, aper.DecodeState) (TAICancelledItemExtIEsExtContainer, aper.Snapshot)
	compare func(TAICancelledItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAICancelledItemExtIEsExtContainerValueCodec) New(value TAICancelledItemExtIEsExtContainer) (TAICancelledItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TAICancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAICancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAICancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAICancelledItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAICancelledItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAICancelledItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAICancelledItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAICancelledItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAICancelledItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAICancelledItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAICancelledItemExtIEsExtContainerValueCodec) EncodeAPER(value TAICancelledItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAICancelledItemExtIEsExtContainerValueCodec) encodeBudgetValue(value TAICancelledItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAICancelledItemExtIEsExtContainerValueCodec) encodeChanged(value TAICancelledItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIExtIEsExtContainerValueCodec is the concrete ValueCodec[TAIExtIEsExtContainer].
type TAIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIExtIEsExtContainer, error)
	encode  func(TAIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIExtIEsExtContainer, aper.DecodeState) (TAIExtIEsExtContainer, aper.Snapshot)
	compare func(TAIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIExtIEsExtContainerValueCodec) New(value TAIExtIEsExtContainer) (TAIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TAIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIExtIEsExtContainerValueCodec) EncodeAPER(value TAIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIExtIEsExtContainerValueCodec) encodeBudgetValue(value TAIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIExtIEsExtContainerValueCodec) encodeChanged(value TAIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemExtIEsExtContainerValueCodec is the concrete ValueCodec[TAIItemExtIEsExtContainer].
type TAIItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItemExtIEsExtContainer, error)
	encode  func(TAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItemExtIEsExtContainer, aper.DecodeState) (TAIItemExtIEsExtContainer, aper.Snapshot)
	compare func(TAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemExtIEsExtContainerValueCodec) New(value TAIItemExtIEsExtContainer) (TAIItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemExtIEsExtContainerValueCodec) EncodeAPER(value TAIItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIItemExtIEsExtContainerValueCodec) encodeBudgetValue(value TAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemExtIEsExtContainerValueCodec) encodeChanged(value TAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetNgRanNodeIDExtIEsExtContainerValueCodec is the concrete ValueCodec[TargetNgRanNodeIDExtIEsExtContainer].
type TargetNgRanNodeIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtContainer, error)
	encode  func(TargetNgRanNodeIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargetNgRanNodeIDExtIEsExtContainer, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtContainer, aper.Snapshot)
	compare func(TargetNgRanNodeIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetNgRanNodeIDExtIEsExtContainerValueCodec) New(value TargetNgRanNodeIDExtIEsExtContainer) (TargetNgRanNodeIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TargetNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetNgRanNodeIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetNgRanNodeIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetNgRanNodeIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetNgRanNodeIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetNgRanNodeIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetNgRanNodeIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetNgRanNodeIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetNgRanNodeIDExtIEsExtContainerValueCodec) EncodeAPER(value TargetNgRanNodeIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargetNgRanNodeIDExtIEsExtContainerValueCodec) encodeBudgetValue(value TargetNgRanNodeIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetNgRanNodeIDExtIEsExtContainerValueCodec) encodeChanged(value TargetNgRanNodeIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetRNCIDExtIEsExtContainerValueCodec is the concrete ValueCodec[TargetRNCIDExtIEsExtContainer].
type TargetRNCIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargetRNCIDExtIEsExtContainer, error)
	encode  func(TargetRNCIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargetRNCIDExtIEsExtContainer, aper.DecodeState) (TargetRNCIDExtIEsExtContainer, aper.Snapshot)
	compare func(TargetRNCIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetRNCIDExtIEsExtContainerValueCodec) New(value TargetRNCIDExtIEsExtContainer) (TargetRNCIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TargetRNCIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetRNCIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetRNCIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetRNCIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetRNCIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetRNCIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetRNCIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetRNCIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetRNCIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetRNCIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetRNCIDExtIEsExtContainerValueCodec) EncodeAPER(value TargetRNCIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargetRNCIDExtIEsExtContainerValueCodec) encodeBudgetValue(value TargetRNCIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetRNCIDExtIEsExtContainerValueCodec) encodeChanged(value TargetRNCIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargeteNBIDExtIEsExtContainerValueCodec is the concrete ValueCodec[TargeteNBIDExtIEsExtContainer].
type TargeteNBIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargeteNBIDExtIEsExtContainer, error)
	encode  func(TargeteNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargeteNBIDExtIEsExtContainer, aper.DecodeState) (TargeteNBIDExtIEsExtContainer, aper.Snapshot)
	compare func(TargeteNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargeteNBIDExtIEsExtContainerValueCodec) New(value TargeteNBIDExtIEsExtContainer) (TargeteNBIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TargeteNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargeteNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargeteNBIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargeteNBIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargeteNBIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargeteNBIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargeteNBIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargeteNBIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargeteNBIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargeteNBIDExtIEsExtContainerValueCodec) EncodeAPER(value TargeteNBIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargeteNBIDExtIEsExtContainerValueCodec) encodeBudgetValue(value TargeteNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargeteNBIDExtIEsExtContainerValueCodec) encodeChanged(value TargeteNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeBasedHandoverInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[TimeBasedHandoverInformationExtIEsExtContainer].
type TimeBasedHandoverInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtContainer, error)
	encode  func(TimeBasedHandoverInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TimeBasedHandoverInformationExtIEsExtContainer, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtContainer, aper.Snapshot)
	compare func(TimeBasedHandoverInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeBasedHandoverInformationExtIEsExtContainerValueCodec) New(value TimeBasedHandoverInformationExtIEsExtContainer) (TimeBasedHandoverInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeBasedHandoverInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeBasedHandoverInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeBasedHandoverInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeBasedHandoverInformationExtIEsExtContainerValueCodec) EncodeAPER(value TimeBasedHandoverInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeBasedHandoverInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value TimeBasedHandoverInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeBasedHandoverInformationExtIEsExtContainerValueCodec) encodeChanged(value TimeBasedHandoverInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorNameConfigExtIEFieldValueCodec is the concrete ValueCodec[SensorNameConfigExtIEField].
type SensorNameConfigExtIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorNameConfigExtIEField, error)
	encode  func(SensorNameConfigExtIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorNameConfigExtIEField, aper.DecodeState) (SensorNameConfigExtIEField, aper.Snapshot)
	compare func(SensorNameConfigExtIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorNameConfigExtIEFieldValueCodec) New(value SensorNameConfigExtIEField) (SensorNameConfigExtIEFieldAPERValue, error) {
	if c.encode == nil {
		return SensorNameConfigExtIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorNameConfigExtIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorNameConfigExtIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorNameConfigExtIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorNameConfigExtIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorNameConfigExtIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorNameConfigExtIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorNameConfigExtIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorNameConfigExtIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorNameConfigExtIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorNameConfigExtIEFieldValueCodec) EncodeAPER(value SensorNameConfigExtIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorNameConfigExtIEFieldValueCodec) encodeBudgetValue(value SensorNameConfigExtIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorNameConfigExtIEFieldValueCodec) encodeChanged(value SensorNameConfigExtIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDExtensionIEIEFieldValueCodec is the concrete ValueCodec[SourceNodeIDExtensionIEIEField].
type SourceNodeIDExtensionIEIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEField, error)
	encode  func(SourceNodeIDExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeIDExtensionIEIEField, aper.DecodeState) (SourceNodeIDExtensionIEIEField, aper.Snapshot)
	compare func(SourceNodeIDExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDExtensionIEIEFieldValueCodec) New(value SourceNodeIDExtensionIEIEField) (SourceNodeIDExtensionIEIEFieldAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDExtensionIEIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDExtensionIEIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDExtensionIEIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDExtensionIEIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDExtensionIEIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDExtensionIEIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDExtensionIEIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDExtensionIEIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDExtensionIEIEFieldValueCodec) EncodeAPER(value SourceNodeIDExtensionIEIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNodeIDExtensionIEIEFieldValueCodec) encodeBudgetValue(value SourceNodeIDExtensionIEIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDExtensionIEIEFieldValueCodec) encodeChanged(value SourceNodeIDExtensionIEIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorNameConfigExtIEContainerValueCodec is the concrete ValueCodec[SensorNameConfigExtIEContainer].
type SensorNameConfigExtIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorNameConfigExtIEContainer, error)
	encode  func(SensorNameConfigExtIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorNameConfigExtIEContainer, aper.DecodeState) (SensorNameConfigExtIEContainer, aper.Snapshot)
	compare func(SensorNameConfigExtIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorNameConfigExtIEContainerValueCodec) New(value SensorNameConfigExtIEContainer) (SensorNameConfigExtIEContainerAPERValue, error) {
	if c.encode == nil {
		return SensorNameConfigExtIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorNameConfigExtIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorNameConfigExtIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorNameConfigExtIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorNameConfigExtIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorNameConfigExtIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorNameConfigExtIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorNameConfigExtIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorNameConfigExtIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorNameConfigExtIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorNameConfigExtIEContainerValueCodec) EncodeAPER(value SensorNameConfigExtIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorNameConfigExtIEContainerValueCodec) encodeBudgetValue(value SensorNameConfigExtIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorNameConfigExtIEContainerValueCodec) encodeChanged(value SensorNameConfigExtIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDExtensionIEIEContainerValueCodec is the concrete ValueCodec[SourceNodeIDExtensionIEIEContainer].
type SourceNodeIDExtensionIEIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEContainer, error)
	encode  func(SourceNodeIDExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeIDExtensionIEIEContainer, aper.DecodeState) (SourceNodeIDExtensionIEIEContainer, aper.Snapshot)
	compare func(SourceNodeIDExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDExtensionIEIEContainerValueCodec) New(value SourceNodeIDExtensionIEIEContainer) (SourceNodeIDExtensionIEIEContainerAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDExtensionIEIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDExtensionIEIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDExtensionIEIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDExtensionIEIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDExtensionIEIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDExtensionIEIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDExtensionIEIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDExtensionIEIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDExtensionIEIEContainerValueCodec) EncodeAPER(value SourceNodeIDExtensionIEIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNodeIDExtensionIEIEContainerValueCodec) encodeBudgetValue(value SourceNodeIDExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDExtensionIEIEContainerValueCodec) encodeChanged(value SourceNodeIDExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[SensorNameConfigExtIEValueProtocolErrorIEContainerList].
type SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorNameConfigExtIEValueProtocolErrorIEContainerList, error)
	encode  func(SensorNameConfigExtIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.DecodeState) (SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) New(value SensorNameConfigExtIEValueProtocolErrorIEContainerList) (SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value SensorNameConfigExtIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value SensorNameConfigExtIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorNameConfigExtIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{SensorNameConfig-ExtIEs}} of TS 36.413: a list of information element fields.
type SensorNameConfigExtIEValueProtocolErrorIEContainerList []SensorNameConfigExtIEValueProtocolIESingleContainer

// SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList].
type SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, error)
	encode  func(SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) New(value SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList) (SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{SourceNodeID-ExtensionIE}} of TS 36.413: a list of information element fields.
type SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList []SourceNodeIDExtensionIEIEValueProtocolIESingleContainer

// SensorNameConfigExtIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[SensorNameConfigExtIEValueProtocolIEContainerList].
type SensorNameConfigExtIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SensorNameConfigExtIEValueProtocolIEContainerList, error)
	encode  func(SensorNameConfigExtIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SensorNameConfigExtIEValueProtocolIEContainerList, aper.DecodeState) (SensorNameConfigExtIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(SensorNameConfigExtIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) New(value SensorNameConfigExtIEValueProtocolIEContainerList) (SensorNameConfigExtIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorNameConfigExtIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorNameConfigExtIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) EncodeAPER(value SensorNameConfigExtIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value SensorNameConfigExtIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) encodeChanged(value SensorNameConfigExtIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorNameConfigExtIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {SensorNameConfig-ExtIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type SensorNameConfigExtIEValueProtocolIEContainerList []SensorNameConfigExtIEValueProtocolIESingleContainer

// SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[SourceNodeIDExtensionIEIEValueProtocolIEContainerList].
type SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolIEContainerList, error)
	encode  func(SourceNodeIDExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) New(value SourceNodeIDExtensionIEIEValueProtocolIEContainerList) (SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) EncodeAPER(value SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value SourceNodeIDExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) encodeChanged(value SourceNodeIDExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDExtensionIEIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {SourceNodeID-ExtensionIE} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type SourceNodeIDExtensionIEIEValueProtocolIEContainerList []SourceNodeIDExtensionIEIEValueProtocolIESingleContainer

// SensorNameConfigExtIEValueERABIEContainerListAPERValue is the concrete APERValue[SensorNameConfigExtIEValueERABIEContainerList].
type SensorNameConfigExtIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorNameConfigExtIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorNameConfigExtIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorNameConfigExtIEValueERABIEContainerListAPERValue) WithoutReplay() SensorNameConfigExtIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue is the concrete APERValue[SourceNodeIDExtensionIEIEValueERABIEContainerList].
type SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceNodeIDExtensionIEIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue) WithoutReplay() SourceNodeIDExtensionIEIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionIEIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{SourceNodeID-ExtensionIE}} of TS 36.413: a single information element field.
type SourceNodeIDExtensionIEIEValueProtocolIESingleContainer = SourceNodeIDExtensionIEIEField

// RequestedTNLInfoExtIEsExtFieldAPERValue is the concrete APERValue[RequestedTNLInfoExtIEsExtField].
type RequestedTNLInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RequestedTNLInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestedTNLInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestedTNLInfoExtIEsExtFieldAPERValue) WithoutReplay() RequestedTNLInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// STMSIExtIEsExtFieldAPERValue is the concrete APERValue[STMSIExtIEsExtField].
type STMSIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         STMSIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v STMSIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v STMSIExtIEsExtFieldAPERValue) WithoutReplay() STMSIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ScheduledCommunicationTimeExtIEsExtFieldAPERValue is the concrete APERValue[ScheduledCommunicationTimeExtIEsExtField].
type ScheduledCommunicationTimeExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ScheduledCommunicationTimeExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ScheduledCommunicationTimeExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ScheduledCommunicationTimeExtIEsExtFieldAPERValue) WithoutReplay() ScheduledCommunicationTimeExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue is the concrete APERValue[SecondaryRATDataUsageReportItemExtIEsExtField].
type SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityContextExtIEsExtFieldAPERValue is the concrete APERValue[SecurityContextExtIEsExtField].
type SecurityContextExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecurityContextExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityContextExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityContextExtIEsExtFieldAPERValue) WithoutReplay() SecurityContextExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityIndicationExtIEsExtFieldAPERValue is the concrete APERValue[SecurityIndicationExtIEsExtField].
type SecurityIndicationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecurityIndicationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityIndicationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityIndicationExtIEsExtFieldAPERValue) WithoutReplay() SecurityIndicationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityResultExtIEsExtFieldAPERValue is the concrete APERValue[SecurityResultExtIEsExtField].
type SecurityResultExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecurityResultExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityResultExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityResultExtIEsExtFieldAPERValue) WithoutReplay() SecurityResultExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorMeasConfigNameItemExtIEsExtFieldAPERValue is the concrete APERValue[SensorMeasConfigNameItemExtIEsExtField].
type SensorMeasConfigNameItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorMeasConfigNameItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasConfigNameItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasConfigNameItemExtIEsExtFieldAPERValue) WithoutReplay() SensorMeasConfigNameItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorMeasurementConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[SensorMeasurementConfigurationExtIEsExtField].
type SensorMeasurementConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorMeasurementConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasurementConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasurementConfigurationExtIEsExtFieldAPERValue) WithoutReplay() SensorMeasurementConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedDCNsItemExtIEsExtFieldAPERValue is the concrete APERValue[ServedDCNsItemExtIEsExtField].
type ServedDCNsItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ServedDCNsItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedDCNsItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedDCNsItemExtIEsExtFieldAPERValue) WithoutReplay() ServedDCNsItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedGUMMEIsItemExtIEsExtFieldAPERValue is the concrete APERValue[ServedGUMMEIsItemExtIEsExtField].
type ServedGUMMEIsItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ServedGUMMEIsItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedGUMMEIsItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedGUMMEIsItemExtIEsExtFieldAPERValue) WithoutReplay() ServedGUMMEIsItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNgRanNodeIDExtIEsExtFieldAPERValue is the concrete APERValue[SourceNgRanNodeIDExtIEsExtField].
type SourceNgRanNodeIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceNgRanNodeIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNgRanNodeIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNgRanNodeIDExtIEsExtFieldAPERValue) WithoutReplay() SourceNgRanNodeIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceeNBIDExtIEsExtFieldAPERValue is the concrete APERValue[SourceeNBIDExtIEsExtField].
type SourceeNBIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceeNBIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceeNBIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBIDExtIEsExtFieldAPERValue) WithoutReplay() SourceeNBIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue is the concrete APERValue[SubscriptionBasedUEDifferentiationInfoExtIEsExtField].
type SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SubscriptionBasedUEDifferentiationInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue) WithoutReplay() SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SupportedTAsItemExtIEsExtFieldAPERValue is the concrete APERValue[SupportedTAsItemExtIEsExtField].
type SupportedTAsItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SupportedTAsItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SupportedTAsItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsItemExtIEsExtFieldAPERValue) WithoutReplay() SupportedTAsItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SynchronisationInformationExtIEsExtFieldAPERValue is the concrete APERValue[SynchronisationInformationExtIEsExtField].
type SynchronisationInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SynchronisationInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SynchronisationInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SynchronisationInformationExtIEsExtFieldAPERValue) WithoutReplay() SynchronisationInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TABasedMDTExtIEsExtFieldAPERValue is the concrete APERValue[TABasedMDTExtIEsExtField].
type TABasedMDTExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TABasedMDTExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TABasedMDTExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedMDTExtIEsExtFieldAPERValue) WithoutReplay() TABasedMDTExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TABasedQMCExtIEsExtFieldAPERValue is the concrete APERValue[TABasedQMCExtIEsExtField].
type TABasedQMCExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TABasedQMCExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TABasedQMCExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedQMCExtIEsExtFieldAPERValue) WithoutReplay() TABasedQMCExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBasedMDTExtIEsExtFieldAPERValue is the concrete APERValue[TAIBasedMDTExtIEsExtField].
type TAIBasedMDTExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIBasedMDTExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedMDTExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedMDTExtIEsExtFieldAPERValue) WithoutReplay() TAIBasedMDTExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBasedQMCExtIEsExtFieldAPERValue is the concrete APERValue[TAIBasedQMCExtIEsExtField].
type TAIBasedQMCExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIBasedQMCExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedQMCExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedQMCExtIEsExtFieldAPERValue) WithoutReplay() TAIBasedQMCExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBroadcastItemExtIEsExtFieldAPERValue is the concrete APERValue[TAIBroadcastItemExtIEsExtField].
type TAIBroadcastItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIBroadcastItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBroadcastItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBroadcastItemExtIEsExtFieldAPERValue) WithoutReplay() TAIBroadcastItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAICancelledItemExtIEsExtFieldAPERValue is the concrete APERValue[TAICancelledItemExtIEsExtField].
type TAICancelledItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAICancelledItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAICancelledItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAICancelledItemExtIEsExtFieldAPERValue) WithoutReplay() TAICancelledItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIExtIEsExtFieldAPERValue is the concrete APERValue[TAIExtIEsExtField].
type TAIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIExtIEsExtFieldAPERValue) WithoutReplay() TAIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIItemExtIEsExtFieldAPERValue is the concrete APERValue[TAIItemExtIEsExtField].
type TAIItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemExtIEsExtFieldAPERValue) WithoutReplay() TAIItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetNgRanNodeIDExtIEsExtFieldAPERValue is the concrete APERValue[TargetNgRanNodeIDExtIEsExtField].
type TargetNgRanNodeIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargetNgRanNodeIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetNgRanNodeIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetNgRanNodeIDExtIEsExtFieldAPERValue) WithoutReplay() TargetNgRanNodeIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetRNCIDExtIEsExtFieldAPERValue is the concrete APERValue[TargetRNCIDExtIEsExtField].
type TargetRNCIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargetRNCIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetRNCIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetRNCIDExtIEsExtFieldAPERValue) WithoutReplay() TargetRNCIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargeteNBIDExtIEsExtFieldAPERValue is the concrete APERValue[TargeteNBIDExtIEsExtField].
type TargeteNBIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargeteNBIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargeteNBIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBIDExtIEsExtFieldAPERValue) WithoutReplay() TargeteNBIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeBasedHandoverInformationExtIEsExtFieldAPERValue is the concrete APERValue[TimeBasedHandoverInformationExtIEsExtField].
type TimeBasedHandoverInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TimeBasedHandoverInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeBasedHandoverInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeBasedHandoverInformationExtIEsExtFieldAPERValue) WithoutReplay() TimeBasedHandoverInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RequestedTNLInfoExtIEsExtContainerAPERValue is the concrete APERValue[RequestedTNLInfoExtIEsExtContainer].
type RequestedTNLInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RequestedTNLInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestedTNLInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestedTNLInfoExtIEsExtContainerAPERValue) WithoutReplay() RequestedTNLInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// STMSIExtIEsExtContainerAPERValue is the concrete APERValue[STMSIExtIEsExtContainer].
type STMSIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         STMSIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v STMSIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v STMSIExtIEsExtContainerAPERValue) WithoutReplay() STMSIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ScheduledCommunicationTimeExtIEsExtContainerAPERValue is the concrete APERValue[ScheduledCommunicationTimeExtIEsExtContainer].
type ScheduledCommunicationTimeExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ScheduledCommunicationTimeExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ScheduledCommunicationTimeExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ScheduledCommunicationTimeExtIEsExtContainerAPERValue) WithoutReplay() ScheduledCommunicationTimeExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue is the concrete APERValue[SecondaryRATDataUsageReportItemExtIEsExtContainer].
type SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityContextExtIEsExtContainerAPERValue is the concrete APERValue[SecurityContextExtIEsExtContainer].
type SecurityContextExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecurityContextExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityContextExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityContextExtIEsExtContainerAPERValue) WithoutReplay() SecurityContextExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityIndicationExtIEsExtContainerAPERValue is the concrete APERValue[SecurityIndicationExtIEsExtContainer].
type SecurityIndicationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecurityIndicationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityIndicationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityIndicationExtIEsExtContainerAPERValue) WithoutReplay() SecurityIndicationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityResultExtIEsExtContainerAPERValue is the concrete APERValue[SecurityResultExtIEsExtContainer].
type SecurityResultExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecurityResultExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityResultExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityResultExtIEsExtContainerAPERValue) WithoutReplay() SecurityResultExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorMeasConfigNameItemExtIEsExtContainerAPERValue is the concrete APERValue[SensorMeasConfigNameItemExtIEsExtContainer].
type SensorMeasConfigNameItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorMeasConfigNameItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasConfigNameItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasConfigNameItemExtIEsExtContainerAPERValue) WithoutReplay() SensorMeasConfigNameItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorMeasurementConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[SensorMeasurementConfigurationExtIEsExtContainer].
type SensorMeasurementConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorMeasurementConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasurementConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasurementConfigurationExtIEsExtContainerAPERValue) WithoutReplay() SensorMeasurementConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedDCNsItemExtIEsExtContainerAPERValue is the concrete APERValue[ServedDCNsItemExtIEsExtContainer].
type ServedDCNsItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ServedDCNsItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedDCNsItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedDCNsItemExtIEsExtContainerAPERValue) WithoutReplay() ServedDCNsItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedGUMMEIsItemExtIEsExtContainerAPERValue is the concrete APERValue[ServedGUMMEIsItemExtIEsExtContainer].
type ServedGUMMEIsItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ServedGUMMEIsItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedGUMMEIsItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedGUMMEIsItemExtIEsExtContainerAPERValue) WithoutReplay() ServedGUMMEIsItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNgRanNodeIDExtIEsExtContainerAPERValue is the concrete APERValue[SourceNgRanNodeIDExtIEsExtContainer].
type SourceNgRanNodeIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceNgRanNodeIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNgRanNodeIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNgRanNodeIDExtIEsExtContainerAPERValue) WithoutReplay() SourceNgRanNodeIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceeNBIDExtIEsExtContainerAPERValue is the concrete APERValue[SourceeNBIDExtIEsExtContainer].
type SourceeNBIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceeNBIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceeNBIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBIDExtIEsExtContainerAPERValue) WithoutReplay() SourceeNBIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue is the concrete APERValue[SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer].
type SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue) WithoutReplay() SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SupportedTAsItemExtIEsExtContainerAPERValue is the concrete APERValue[SupportedTAsItemExtIEsExtContainer].
type SupportedTAsItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SupportedTAsItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SupportedTAsItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsItemExtIEsExtContainerAPERValue) WithoutReplay() SupportedTAsItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SynchronisationInformationExtIEsExtContainerAPERValue is the concrete APERValue[SynchronisationInformationExtIEsExtContainer].
type SynchronisationInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SynchronisationInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SynchronisationInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SynchronisationInformationExtIEsExtContainerAPERValue) WithoutReplay() SynchronisationInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TABasedMDTExtIEsExtContainerAPERValue is the concrete APERValue[TABasedMDTExtIEsExtContainer].
type TABasedMDTExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TABasedMDTExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TABasedMDTExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedMDTExtIEsExtContainerAPERValue) WithoutReplay() TABasedMDTExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TABasedQMCExtIEsExtContainerAPERValue is the concrete APERValue[TABasedQMCExtIEsExtContainer].
type TABasedQMCExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TABasedQMCExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TABasedQMCExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedQMCExtIEsExtContainerAPERValue) WithoutReplay() TABasedQMCExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBasedMDTExtIEsExtContainerAPERValue is the concrete APERValue[TAIBasedMDTExtIEsExtContainer].
type TAIBasedMDTExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIBasedMDTExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedMDTExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedMDTExtIEsExtContainerAPERValue) WithoutReplay() TAIBasedMDTExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBasedQMCExtIEsExtContainerAPERValue is the concrete APERValue[TAIBasedQMCExtIEsExtContainer].
type TAIBasedQMCExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIBasedQMCExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedQMCExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedQMCExtIEsExtContainerAPERValue) WithoutReplay() TAIBasedQMCExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBroadcastItemExtIEsExtContainerAPERValue is the concrete APERValue[TAIBroadcastItemExtIEsExtContainer].
type TAIBroadcastItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIBroadcastItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBroadcastItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBroadcastItemExtIEsExtContainerAPERValue) WithoutReplay() TAIBroadcastItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAICancelledItemExtIEsExtContainerAPERValue is the concrete APERValue[TAICancelledItemExtIEsExtContainer].
type TAICancelledItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAICancelledItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAICancelledItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAICancelledItemExtIEsExtContainerAPERValue) WithoutReplay() TAICancelledItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIExtIEsExtContainerAPERValue is the concrete APERValue[TAIExtIEsExtContainer].
type TAIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIExtIEsExtContainerAPERValue) WithoutReplay() TAIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIItemExtIEsExtContainerAPERValue is the concrete APERValue[TAIItemExtIEsExtContainer].
type TAIItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemExtIEsExtContainerAPERValue) WithoutReplay() TAIItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetNgRanNodeIDExtIEsExtContainerAPERValue is the concrete APERValue[TargetNgRanNodeIDExtIEsExtContainer].
type TargetNgRanNodeIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargetNgRanNodeIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetNgRanNodeIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetNgRanNodeIDExtIEsExtContainerAPERValue) WithoutReplay() TargetNgRanNodeIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetRNCIDExtIEsExtContainerAPERValue is the concrete APERValue[TargetRNCIDExtIEsExtContainer].
type TargetRNCIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargetRNCIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetRNCIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetRNCIDExtIEsExtContainerAPERValue) WithoutReplay() TargetRNCIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargeteNBIDExtIEsExtContainerAPERValue is the concrete APERValue[TargeteNBIDExtIEsExtContainer].
type TargeteNBIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargeteNBIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargeteNBIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBIDExtIEsExtContainerAPERValue) WithoutReplay() TargeteNBIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeBasedHandoverInformationExtIEsExtContainerAPERValue is the concrete APERValue[TimeBasedHandoverInformationExtIEsExtContainer].
type TimeBasedHandoverInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TimeBasedHandoverInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeBasedHandoverInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeBasedHandoverInformationExtIEsExtContainerAPERValue) WithoutReplay() TimeBasedHandoverInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeSynchronisationInfoExtIEsExtContainerAPERValue is the concrete APERValue[TimeSynchronisationInfoExtIEsExtContainer].
type TimeSynchronisationInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TimeSynchronisationInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeSynchronisationInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeSynchronisationInfoExtIEsExtContainerAPERValue) WithoutReplay() TimeSynchronisationInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorNameConfigExtIEFieldAPERValue is the concrete APERValue[SensorNameConfigExtIEField].
type SensorNameConfigExtIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorNameConfigExtIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorNameConfigExtIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorNameConfigExtIEFieldAPERValue) WithoutReplay() SensorNameConfigExtIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionIEIEFieldAPERValue is the concrete APERValue[SourceNodeIDExtensionIEIEField].
type SourceNodeIDExtensionIEIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceNodeIDExtensionIEIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDExtensionIEIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionIEIEFieldAPERValue) WithoutReplay() SourceNodeIDExtensionIEIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorNameConfigExtIEContainerAPERValue is the concrete APERValue[SensorNameConfigExtIEContainer].
type SensorNameConfigExtIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorNameConfigExtIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorNameConfigExtIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorNameConfigExtIEContainerAPERValue) WithoutReplay() SensorNameConfigExtIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionIEIEContainerAPERValue is the concrete APERValue[SourceNodeIDExtensionIEIEContainer].
type SourceNodeIDExtensionIEIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceNodeIDExtensionIEIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDExtensionIEIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionIEIEContainerAPERValue) WithoutReplay() SourceNodeIDExtensionIEIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[SensorNameConfigExtIEValueProtocolErrorIEContainerList].
type SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorNameConfigExtIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() SensorNameConfigExtIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList].
type SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorNameConfigExtIEValueProtocolIEContainerListAPERValue is the concrete APERValue[SensorNameConfigExtIEValueProtocolIEContainerList].
type SensorNameConfigExtIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SensorNameConfigExtIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorNameConfigExtIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorNameConfigExtIEValueProtocolIEContainerListAPERValue) WithoutReplay() SensorNameConfigExtIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue is the concrete APERValue[SourceNodeIDExtensionIEIEValueProtocolIEContainerList].
type SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceNodeIDExtensionIEIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue) WithoutReplay() SourceNodeIDExtensionIEIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type RequestedTNLInfoExtIETable struct{}

func RequestedTNLInfoExtIEs() RequestedTNLInfoExtIETable { return RequestedTNLInfoExtIETable{} }

// ID returns the ASN.1 object-set identity of RequestedTNLInfoExtIETable.
func (RequestedTNLInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestedTNLInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RequestedTNLInfoExtIETable.
func (RequestedTNLInfoExtIETable) Table() s00.RequestedTNLInfoExtIEsValueExtensionTable {
	return func() s00.RequestedTNLInfoExtIEsValueExtensionTable {
		sealed := s00.RequestedTNLInfoExtIEsValueExtensionTable{}
		*s00.BridgeRequestedTNLInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RequestedTNLInfoExtIETable.
func (t RequestedTNLInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RequestedTNLInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RequestedTNLInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RequestedTNLInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RequestedTNLInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RequestedTNLInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RequestedTNLInfoExtIEsValue {
			sealed := s06.RequestedTNLInfoExtIEsValue{}
			*s06.BridgeRequestedTNLInfoExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRequestedTNLInfoExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRequestedTNLInfoExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type STMSIExtIETable struct{}

func STMSIExtIEs() STMSIExtIETable { return STMSIExtIETable{} }

// ID returns the ASN.1 object-set identity of STMSIExtIETable.
func (STMSIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by STMSIExtIETable.
func (STMSIExtIETable) Table() s00.STMSIExtIEsValueExtensionTable {
	return func() s00.STMSIExtIEsValueExtensionTable {
		sealed := s00.STMSIExtIEsValueExtensionTable{}
		*s00.BridgeSTMSIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in STMSIExtIETable.
func (t STMSIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (STMSIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return STMSIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return STMSIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return STMSIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return STMSIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.STMSIExtIEsValue {
			sealed := s06.STMSIExtIEsValue{}
			*s06.BridgeSTMSIExtIEsValueFieldId(&sealed) = id
			*s06.BridgeSTMSIExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeSTMSIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ScheduledCommunicationTimeExtIETable struct{}

func ScheduledCommunicationTimeExtIEs() ScheduledCommunicationTimeExtIETable {
	return ScheduledCommunicationTimeExtIETable{}
}

// ID returns the ASN.1 object-set identity of ScheduledCommunicationTimeExtIETable.
func (ScheduledCommunicationTimeExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ScheduledCommunicationTime-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ScheduledCommunicationTimeExtIETable.
func (ScheduledCommunicationTimeExtIETable) Table() s00.ScheduledCommunicationTimeExtIEsValueExtensionTable {
	return func() s00.ScheduledCommunicationTimeExtIEsValueExtensionTable {
		sealed := s00.ScheduledCommunicationTimeExtIEsValueExtensionTable{}
		*s00.BridgeScheduledCommunicationTimeExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ScheduledCommunicationTimeExtIETable.
func (t ScheduledCommunicationTimeExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ScheduledCommunicationTimeExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ScheduledCommunicationTimeExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ScheduledCommunicationTimeExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ScheduledCommunicationTimeExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ScheduledCommunicationTimeExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.ScheduledCommunicationTimeExtIEsValue {
			sealed := s06.ScheduledCommunicationTimeExtIEsValue{}
			*s06.BridgeScheduledCommunicationTimeExtIEsValueFieldId(&sealed) = id
			*s06.BridgeScheduledCommunicationTimeExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeScheduledCommunicationTimeExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SecondaryRATDataUsageReportItemExtIETable struct{}

func SecondaryRATDataUsageReportItemExtIEs() SecondaryRATDataUsageReportItemExtIETable {
	return SecondaryRATDataUsageReportItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of SecondaryRATDataUsageReportItemExtIETable.
func (SecondaryRATDataUsageReportItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SecondaryRATDataUsageReportItemExtIETable.
func (SecondaryRATDataUsageReportItemExtIETable) Table() s00.SecondaryRATDataUsageReportItemExtIEsValueExtensionTable {
	return func() s00.SecondaryRATDataUsageReportItemExtIEsValueExtensionTable {
		sealed := s00.SecondaryRATDataUsageReportItemExtIEsValueExtensionTable{}
		*s00.BridgeSecondaryRATDataUsageReportItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SecondaryRATDataUsageReportItemExtIETable.
func (t SecondaryRATDataUsageReportItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SecondaryRATDataUsageReportItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SecondaryRATDataUsageReportItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SecondaryRATDataUsageReportItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SecondaryRATDataUsageReportItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SecondaryRATDataUsageReportItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.SecondaryRATDataUsageReportItemExtIEsValue {
			sealed := s06.SecondaryRATDataUsageReportItemExtIEsValue{}
			*s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueFieldId(&sealed) = id
			*s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SecurityContextExtIETable struct{}

func SecurityContextExtIEs() SecurityContextExtIETable { return SecurityContextExtIETable{} }

// ID returns the ASN.1 object-set identity of SecurityContextExtIETable.
func (SecurityContextExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityContext-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SecurityContextExtIETable.
func (SecurityContextExtIETable) Table() s00.SecurityContextExtIEsValueExtensionTable {
	return func() s00.SecurityContextExtIEsValueExtensionTable {
		sealed := s00.SecurityContextExtIEsValueExtensionTable{}
		*s00.BridgeSecurityContextExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SecurityContextExtIETable.
func (t SecurityContextExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SecurityContextExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SecurityContextExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SecurityContextExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SecurityContextExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SecurityContextExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.SecurityContextExtIEsValue {
			sealed := s06.SecurityContextExtIEsValue{}
			*s06.BridgeSecurityContextExtIEsValueFieldId(&sealed) = id
			*s06.BridgeSecurityContextExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeSecurityContextExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SecurityIndicationExtIETable struct{}

func SecurityIndicationExtIEs() SecurityIndicationExtIETable { return SecurityIndicationExtIETable{} }

// ID returns the ASN.1 object-set identity of SecurityIndicationExtIETable.
func (SecurityIndicationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityIndication-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SecurityIndicationExtIETable.
func (SecurityIndicationExtIETable) Table() s00.SecurityIndicationExtIEsValueExtensionTable {
	return func() s00.SecurityIndicationExtIEsValueExtensionTable {
		sealed := s00.SecurityIndicationExtIEsValueExtensionTable{}
		*s00.BridgeSecurityIndicationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SecurityIndicationExtIETable.
func (t SecurityIndicationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SecurityIndicationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SecurityIndicationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SecurityIndicationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SecurityIndicationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SecurityIndicationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.SecurityIndicationExtIEsValue {
			sealed := s06.SecurityIndicationExtIEsValue{}
			*s06.BridgeSecurityIndicationExtIEsValueFieldId(&sealed) = id
			*s06.BridgeSecurityIndicationExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeSecurityIndicationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SecurityResultExtIETable struct{}

func SecurityResultExtIEs() SecurityResultExtIETable { return SecurityResultExtIETable{} }

// ID returns the ASN.1 object-set identity of SecurityResultExtIETable.
func (SecurityResultExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityResult-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SecurityResultExtIETable.
func (SecurityResultExtIETable) Table() s00.SecurityResultExtIEsValueExtensionTable {
	return func() s00.SecurityResultExtIEsValueExtensionTable {
		sealed := s00.SecurityResultExtIEsValueExtensionTable{}
		*s00.BridgeSecurityResultExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SecurityResultExtIETable.
func (t SecurityResultExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SecurityResultExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SecurityResultExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SecurityResultExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SecurityResultExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SecurityResultExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.SecurityResultExtIEsValue {
			sealed := s06.SecurityResultExtIEsValue{}
			*s06.BridgeSecurityResultExtIEsValueFieldId(&sealed) = id
			*s06.BridgeSecurityResultExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeSecurityResultExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SensorMeasConfigNameItemExtIETable struct{}

func SensorMeasConfigNameItemExtIEs() SensorMeasConfigNameItemExtIETable {
	return SensorMeasConfigNameItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of SensorMeasConfigNameItemExtIETable.
func (SensorMeasConfigNameItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SensorMeasConfigNameItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SensorMeasConfigNameItemExtIETable.
func (SensorMeasConfigNameItemExtIETable) Table() s00.SensorMeasConfigNameItemExtIEsValueExtensionTable {
	return func() s00.SensorMeasConfigNameItemExtIEsValueExtensionTable {
		sealed := s00.SensorMeasConfigNameItemExtIEsValueExtensionTable{}
		*s00.BridgeSensorMeasConfigNameItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SensorMeasConfigNameItemExtIETable.
func (t SensorMeasConfigNameItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SensorMeasConfigNameItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SensorMeasConfigNameItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SensorMeasConfigNameItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SensorMeasConfigNameItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SensorMeasConfigNameItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.SensorMeasConfigNameItemExtIEsValue {
			sealed := s06.SensorMeasConfigNameItemExtIEsValue{}
			*s06.BridgeSensorMeasConfigNameItemExtIEsValueFieldId(&sealed) = id
			*s06.BridgeSensorMeasConfigNameItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeSensorMeasConfigNameItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SensorMeasurementConfigurationExtIETable struct{}

func SensorMeasurementConfigurationExtIEs() SensorMeasurementConfigurationExtIETable {
	return SensorMeasurementConfigurationExtIETable{}
}

// ID returns the ASN.1 object-set identity of SensorMeasurementConfigurationExtIETable.
func (SensorMeasurementConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SensorMeasurementConfiguration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SensorMeasurementConfigurationExtIETable.
func (SensorMeasurementConfigurationExtIETable) Table() s00.SensorMeasurementConfigurationExtIEsValueExtensionTable {
	return func() s00.SensorMeasurementConfigurationExtIEsValueExtensionTable {
		sealed := s00.SensorMeasurementConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeSensorMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SensorMeasurementConfigurationExtIETable.
func (t SensorMeasurementConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SensorMeasurementConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SensorMeasurementConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SensorMeasurementConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SensorMeasurementConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SensorMeasurementConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.SensorMeasurementConfigurationExtIEsValue {
			sealed := s07.SensorMeasurementConfigurationExtIEsValue{}
			*s07.BridgeSensorMeasurementConfigurationExtIEsValueFieldId(&sealed) = id
			*s07.BridgeSensorMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeSensorMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SensorNameConfigExtIETable struct{}

func SensorNameConfigExtIEs() SensorNameConfigExtIETable { return SensorNameConfigExtIETable{} }

// ID returns the ASN.1 object-set identity of SensorNameConfigExtIETable.
func (SensorNameConfigExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SensorNameConfig-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SensorNameConfigExtIETable.
func (SensorNameConfigExtIETable) Table() s00.SensorNameConfigExtIEValueIETable {
	return func() s00.SensorNameConfigExtIEValueIETable {
		sealed := s00.SensorNameConfigExtIEValueIETable{}
		*s00.BridgeSensorNameConfigExtIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SensorNameConfigExtIETable.
func (t SensorNameConfigExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (SensorNameConfigExtIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SensorNameConfigExtIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SensorNameConfigExtIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SensorNameConfigExtIEField{}, aper.OperationError(err, "Opaque")
		}
		return SensorNameConfigExtIEField{Id: id, Criticality: criticality, Value: func() s07.SensorNameConfigExtIEValue {
			sealed := s07.SensorNameConfigExtIEValue{}
			*s07.BridgeSensorNameConfigExtIEValueFieldId(&sealed) = id
			*s07.BridgeSensorNameConfigExtIEValueFieldOpaque(&sealed) = opaque
			*s07.BridgeSensorNameConfigExtIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ServedDCNsItemExtIETable struct{}

func ServedDCNsItemExtIEs() ServedDCNsItemExtIETable { return ServedDCNsItemExtIETable{} }

// ID returns the ASN.1 object-set identity of ServedDCNsItemExtIETable.
func (ServedDCNsItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ServedDCNsItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ServedDCNsItemExtIETable.
func (ServedDCNsItemExtIETable) Table() s00.ServedDCNsItemExtIEsValueExtensionTable {
	return func() s00.ServedDCNsItemExtIEsValueExtensionTable {
		sealed := s00.ServedDCNsItemExtIEsValueExtensionTable{}
		*s00.BridgeServedDCNsItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ServedDCNsItemExtIETable.
func (t ServedDCNsItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ServedDCNsItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ServedDCNsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ServedDCNsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ServedDCNsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ServedDCNsItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.ServedDCNsItemExtIEsValue {
			sealed := s07.ServedDCNsItemExtIEsValue{}
			*s07.BridgeServedDCNsItemExtIEsValueFieldId(&sealed) = id
			*s07.BridgeServedDCNsItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeServedDCNsItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ServedGUMMEIsItemExtIETable struct{}

func ServedGUMMEIsItemExtIEs() ServedGUMMEIsItemExtIETable { return ServedGUMMEIsItemExtIETable{} }

// ID returns the ASN.1 object-set identity of ServedGUMMEIsItemExtIETable.
func (ServedGUMMEIsItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ServedGUMMEIsItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ServedGUMMEIsItemExtIETable.
func (ServedGUMMEIsItemExtIETable) Table() s00.ServedGUMMEIsItemExtIEsValueExtensionTable {
	return func() s00.ServedGUMMEIsItemExtIEsValueExtensionTable {
		sealed := s00.ServedGUMMEIsItemExtIEsValueExtensionTable{}
		*s00.BridgeServedGUMMEIsItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ServedGUMMEIsItemExtIETable) infoGUMMEIType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ServedGUMMEIsItemExtIEs().ID(), ID: s00.ProtocolExtensionID(170), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEIType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ServedGUMMEIsItem-ExtIEs", Row: "id-GUMMEIType"}}}
}

// GUMMEIType returns the typed binding for the GUMMEIType row of ServedGUMMEIsItemExtIETable.
func (t ServedGUMMEIsItemExtIETable) GUMMEIType() ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding {
	return ServedGUMMEIsItemExtIEsGUMMEITypeExtBinding{info: t.infoGUMMEIType(), codec: func() s01.GUMMEITypeValueCodec {
		sealed := s01.GUMMEITypeValueCodec{}
		*s01.BridgeGUMMEITypeValueCodecFieldPath(&sealed) = "GUMMEIType"
		*s01.BridgeGUMMEITypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GUMMEIType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.GUMMEIType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GUMMEIType")
			var zero s07.ServedGUMMEIsItemExtIEsValue
			decoded, err := s07.BridgeServedGUMMEIsItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(170), raw)
			if err != nil {
				var empty s00.GUMMEIType
				return empty, runtime.WrapDecodePath(err, "GUMMEIType")
			}
			value, ok := decoded.AsGUMMEIType()
			if !ok {
				var empty s00.GUMMEIType
				return empty, fmt.Errorf("binding ServedGUMMEIsItem-ExtIEs.id-GUMMEIType: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeGUMMEITypeValueCodecFieldEncode(&sealed) = func(value s00.GUMMEIType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s07.BridgeServedGUMMEIsItemExtIEsValueMethodEncodeFresh((func() s07.ServedGUMMEIsItemExtIEsValue {
				sealed := s07.ServedGUMMEIsItemExtIEsValue{}
				*s07.BridgeServedGUMMEIsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(170)
				*s07.BridgeServedGUMMEIsItemExtIEsValueFieldRowGUMMEIType(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeGUMMEITypeValueCodecFieldCapture(&sealed) = func(v s00.GUMMEIType, options aper.DecodeState) (s00.GUMMEIType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APGUMMEIType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeGUMMEITypeValueCodecFieldCompare(&sealed) = func(v s00.GUMMEIType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APGUMMEIType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeGUMMEITypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GUMMEIType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.GUMMEIType) s07.ServedGUMMEIsItemExtIEsValue {
			return func() s07.ServedGUMMEIsItemExtIEsValue {
				sealed := s07.ServedGUMMEIsItemExtIEsValue{}
				*s07.BridgeServedGUMMEIsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(170)
				*s07.BridgeServedGUMMEIsItemExtIEsValueFieldRowGUMMEIType(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s07.ServedGUMMEIsItemExtIEsValue) (*s00.GUMMEIType, bool) { return value.AsGUMMEIType() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ServedGUMMEIsItemExtIETable.
func (t ServedGUMMEIsItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ServedGUMMEIsItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(170):
		return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-GUMMEIType requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ServedGUMMEIsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ServedGUMMEIsItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.ServedGUMMEIsItemExtIEsValue {
			sealed := s07.ServedGUMMEIsItemExtIEsValue{}
			*s07.BridgeServedGUMMEIsItemExtIEsValueFieldId(&sealed) = id
			*s07.BridgeServedGUMMEIsItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeServedGUMMEIsItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SourceNgRanNodeIDExtIETable struct{}

func SourceNgRanNodeIDExtIEs() SourceNgRanNodeIDExtIETable { return SourceNgRanNodeIDExtIETable{} }

// ID returns the ASN.1 object-set identity of SourceNgRanNodeIDExtIETable.
func (SourceNgRanNodeIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceNgRanNode-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SourceNgRanNodeIDExtIETable.
func (SourceNgRanNodeIDExtIETable) Table() s00.SourceNgRanNodeIDExtIEsValueExtensionTable {
	return func() s00.SourceNgRanNodeIDExtIEsValueExtensionTable {
		sealed := s00.SourceNgRanNodeIDExtIEsValueExtensionTable{}
		*s00.BridgeSourceNgRanNodeIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SourceNgRanNodeIDExtIETable.
func (t SourceNgRanNodeIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SourceNgRanNodeIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SourceNgRanNodeIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SourceNgRanNodeIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SourceNgRanNodeIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SourceNgRanNodeIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.SourceNgRanNodeIDExtIEsValue {
			sealed := s07.SourceNgRanNodeIDExtIEsValue{}
			*s07.BridgeSourceNgRanNodeIDExtIEsValueFieldId(&sealed) = id
			*s07.BridgeSourceNgRanNodeIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeSourceNgRanNodeIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SourceNodeIDExtensionIETable struct{}

func SourceNodeIDExtensionIE() SourceNodeIDExtensionIETable { return SourceNodeIDExtensionIETable{} }

// ID returns the ASN.1 object-set identity of SourceNodeIDExtensionIETable.
func (SourceNodeIDExtensionIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceNodeID-ExtensionIE"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SourceNodeIDExtensionIETable.
func (SourceNodeIDExtensionIETable) Table() s00.SourceNodeIDExtensionIEIEValueIETable {
	return func() s00.SourceNodeIDExtensionIEIEValueIETable {
		sealed := s00.SourceNodeIDExtensionIEIEValueIETable{}
		*s00.BridgeSourceNodeIDExtensionIEIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SourceNodeIDExtensionIETable.
func (t SourceNodeIDExtensionIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (SourceNodeIDExtensionIEIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SourceNodeIDExtensionIEIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SourceNodeIDExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SourceNodeIDExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		return SourceNodeIDExtensionIEIEField{Id: id, Criticality: criticality, Value: func() s07.SourceNodeIDExtensionIEIEValue {
			sealed := s07.SourceNodeIDExtensionIEIEValue{}
			*s07.BridgeSourceNodeIDExtensionIEIEValueFieldId(&sealed) = id
			*s07.BridgeSourceNodeIDExtensionIEIEValueFieldOpaque(&sealed) = opaque
			*s07.BridgeSourceNodeIDExtensionIEIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SourceeNBIDExtIETable struct{}

func SourceeNBIDExtIEs() SourceeNBIDExtIETable { return SourceeNBIDExtIETable{} }

// ID returns the ASN.1 object-set identity of SourceeNBIDExtIETable.
func (SourceeNBIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SourceeNBIDExtIETable.
func (SourceeNBIDExtIETable) Table() s00.SourceeNBIDExtIEsValueExtensionTable {
	return func() s00.SourceeNBIDExtIEsValueExtensionTable {
		sealed := s00.SourceeNBIDExtIEsValueExtensionTable{}
		*s00.BridgeSourceeNBIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SourceeNBIDExtIETable.
func (t SourceeNBIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SourceeNBIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SourceeNBIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SourceeNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SourceeNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SourceeNBIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.SourceeNBIDExtIEsValue {
			sealed := s07.SourceeNBIDExtIEsValue{}
			*s07.BridgeSourceeNBIDExtIEsValueFieldId(&sealed) = id
			*s07.BridgeSourceeNBIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeSourceeNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SubscriptionBasedUEDifferentiationInfoExtIETable struct{}

func SubscriptionBasedUEDifferentiationInfoExtIEs() SubscriptionBasedUEDifferentiationInfoExtIETable {
	return SubscriptionBasedUEDifferentiationInfoExtIETable{}
}

// ID returns the ASN.1 object-set identity of SubscriptionBasedUEDifferentiationInfoExtIETable.
func (SubscriptionBasedUEDifferentiationInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SubscriptionBasedUEDifferentiationInfoExtIETable.
func (SubscriptionBasedUEDifferentiationInfoExtIETable) Table() s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable {
	return func() s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable {
		sealed := s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable{}
		*s00.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SubscriptionBasedUEDifferentiationInfoExtIETable.
func (t SubscriptionBasedUEDifferentiationInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SubscriptionBasedUEDifferentiationInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SubscriptionBasedUEDifferentiationInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SubscriptionBasedUEDifferentiationInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SubscriptionBasedUEDifferentiationInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue {
			sealed := s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue{}
			*s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueFieldId(&sealed) = id
			*s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SupportedTAsItemExtIETable struct{}

func SupportedTAsItemExtIEs() SupportedTAsItemExtIETable { return SupportedTAsItemExtIETable{} }

// ID returns the ASN.1 object-set identity of SupportedTAsItemExtIETable.
func (SupportedTAsItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SupportedTAs-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SupportedTAsItemExtIETable.
func (SupportedTAsItemExtIETable) Table() s00.SupportedTAsItemExtIEsValueExtensionTable {
	return func() s00.SupportedTAsItemExtIEsValueExtensionTable {
		sealed := s00.SupportedTAsItemExtIEsValueExtensionTable{}
		*s00.BridgeSupportedTAsItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SupportedTAsItemExtIETable) infoRATType() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SupportedTAsItemExtIEs().ID(), ID: s00.ProtocolExtensionID(232), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RAT-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SupportedTAs-Item-ExtIEs", Row: "id-RAT-Type"}}}
}

// RATType returns the typed binding for the RATType row of SupportedTAsItemExtIETable.
func (t SupportedTAsItemExtIETable) RATType() SupportedTAsItemExtIEsRATTypeExtBinding {
	return SupportedTAsItemExtIEsRATTypeExtBinding{info: t.infoRATType(), codec: func() s01.RATTypeValueCodec {
		sealed := s01.RATTypeValueCodec{}
		*s01.BridgeRATTypeValueCodecFieldPath(&sealed) = "RATType"
		*s01.BridgeRATTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RATType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RATType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RATType")
			var zero s08.SupportedTAsItemExtIEsValue
			decoded, err := s08.BridgeSupportedTAsItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(232), raw)
			if err != nil {
				var empty s00.RATType
				return empty, runtime.WrapDecodePath(err, "RATType")
			}
			value, ok := decoded.AsRATType()
			if !ok {
				var empty s00.RATType
				return empty, fmt.Errorf("binding SupportedTAs-Item-ExtIEs.id-RAT-Type: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRATTypeValueCodecFieldEncode(&sealed) = func(value s00.RATType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s08.BridgeSupportedTAsItemExtIEsValueMethodEncodeFresh((func() s08.SupportedTAsItemExtIEsValue {
				sealed := s08.SupportedTAsItemExtIEsValue{}
				*s08.BridgeSupportedTAsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(232)
				*s08.BridgeSupportedTAsItemExtIEsValueFieldRowRATType(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeRATTypeValueCodecFieldCapture(&sealed) = func(v s00.RATType, options aper.DecodeState) (s00.RATType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APRATType(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeRATTypeValueCodecFieldCompare(&sealed) = func(v s00.RATType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRATType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRATTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RATType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RATType) s08.SupportedTAsItemExtIEsValue {
			return func() s08.SupportedTAsItemExtIEsValue {
				sealed := s08.SupportedTAsItemExtIEsValue{}
				*s08.BridgeSupportedTAsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(232)
				*s08.BridgeSupportedTAsItemExtIEsValueFieldRowRATType(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s08.SupportedTAsItemExtIEsValue) (*s00.RATType, bool) { return value.AsRATType() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SupportedTAsItemExtIETable.
func (t SupportedTAsItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SupportedTAsItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SupportedTAsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(232):
		return SupportedTAsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-RAT-Type requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SupportedTAsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SupportedTAsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SupportedTAsItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s08.SupportedTAsItemExtIEsValue {
			sealed := s08.SupportedTAsItemExtIEsValue{}
			*s08.BridgeSupportedTAsItemExtIEsValueFieldId(&sealed) = id
			*s08.BridgeSupportedTAsItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s08.BridgeSupportedTAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SynchronisationInformationExtIETable struct{}

func SynchronisationInformationExtIEs() SynchronisationInformationExtIETable {
	return SynchronisationInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of SynchronisationInformationExtIETable.
func (SynchronisationInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SynchronisationInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SynchronisationInformationExtIETable.
func (SynchronisationInformationExtIETable) Table() s00.SynchronisationInformationExtIEsValueExtensionTable {
	return func() s00.SynchronisationInformationExtIEsValueExtensionTable {
		sealed := s00.SynchronisationInformationExtIEsValueExtensionTable{}
		*s00.BridgeSynchronisationInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SynchronisationInformationExtIETable.
func (t SynchronisationInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SynchronisationInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SynchronisationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SynchronisationInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SynchronisationInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SynchronisationInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.SynchronisationInformationExtIEsValue {
			sealed := s07.SynchronisationInformationExtIEsValue{}
			*s07.BridgeSynchronisationInformationExtIEsValueFieldId(&sealed) = id
			*s07.BridgeSynchronisationInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeSynchronisationInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TABasedMDTExtIETable struct{}

func TABasedMDTExtIEs() TABasedMDTExtIETable { return TABasedMDTExtIETable{} }

// ID returns the ASN.1 object-set identity of TABasedMDTExtIETable.
func (TABasedMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TABasedMDT-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TABasedMDTExtIETable.
func (TABasedMDTExtIETable) Table() s00.TABasedMDTExtIEsValueExtensionTable {
	return func() s00.TABasedMDTExtIEsValueExtensionTable {
		sealed := s00.TABasedMDTExtIEsValueExtensionTable{}
		*s00.BridgeTABasedMDTExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TABasedMDTExtIETable.
func (t TABasedMDTExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TABasedMDTExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TABasedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TABasedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TABasedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TABasedMDTExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TABasedMDTExtIEsValue {
			sealed := s07.TABasedMDTExtIEsValue{}
			*s07.BridgeTABasedMDTExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTABasedMDTExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTABasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TABasedQMCExtIETable struct{}

func TABasedQMCExtIEs() TABasedQMCExtIETable { return TABasedQMCExtIETable{} }

// ID returns the ASN.1 object-set identity of TABasedQMCExtIETable.
func (TABasedQMCExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TABasedQMC-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TABasedQMCExtIETable.
func (TABasedQMCExtIETable) Table() s00.TABasedQMCExtIEsValueExtensionTable {
	return func() s00.TABasedQMCExtIEsValueExtensionTable {
		sealed := s00.TABasedQMCExtIEsValueExtensionTable{}
		*s00.BridgeTABasedQMCExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TABasedQMCExtIETable.
func (t TABasedQMCExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TABasedQMCExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TABasedQMCExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TABasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TABasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TABasedQMCExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TABasedQMCExtIEsValue {
			sealed := s07.TABasedQMCExtIEsValue{}
			*s07.BridgeTABasedQMCExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTABasedQMCExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTABasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TAIBroadcastItemExtIETable struct{}

func TAIBroadcastItemExtIEs() TAIBroadcastItemExtIETable { return TAIBroadcastItemExtIETable{} }

// ID returns the ASN.1 object-set identity of TAIBroadcastItemExtIETable.
func (TAIBroadcastItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI-Broadcast-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TAIBroadcastItemExtIETable.
func (TAIBroadcastItemExtIETable) Table() s00.TAIBroadcastItemExtIEsValueExtensionTable {
	return func() s00.TAIBroadcastItemExtIEsValueExtensionTable {
		sealed := s00.TAIBroadcastItemExtIEsValueExtensionTable{}
		*s00.BridgeTAIBroadcastItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TAIBroadcastItemExtIETable.
func (t TAIBroadcastItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TAIBroadcastItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TAIBroadcastItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TAIBroadcastItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TAIBroadcastItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TAIBroadcastItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TAIBroadcastItemExtIEsValue {
			sealed := s07.TAIBroadcastItemExtIEsValue{}
			*s07.BridgeTAIBroadcastItemExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTAIBroadcastItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTAIBroadcastItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TAICancelledItemExtIETable struct{}

func TAICancelledItemExtIEs() TAICancelledItemExtIETable { return TAICancelledItemExtIETable{} }

// ID returns the ASN.1 object-set identity of TAICancelledItemExtIETable.
func (TAICancelledItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI-Cancelled-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TAICancelledItemExtIETable.
func (TAICancelledItemExtIETable) Table() s00.TAICancelledItemExtIEsValueExtensionTable {
	return func() s00.TAICancelledItemExtIEsValueExtensionTable {
		sealed := s00.TAICancelledItemExtIEsValueExtensionTable{}
		*s00.BridgeTAICancelledItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TAICancelledItemExtIETable.
func (t TAICancelledItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TAICancelledItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TAICancelledItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TAICancelledItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TAICancelledItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TAICancelledItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TAICancelledItemExtIEsValue {
			sealed := s07.TAICancelledItemExtIEsValue{}
			*s07.BridgeTAICancelledItemExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTAICancelledItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTAICancelledItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TAIExtIETable struct{}

func TAIExtIEs() TAIExtIETable { return TAIExtIETable{} }

// ID returns the ASN.1 object-set identity of TAIExtIETable.
func (TAIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TAIExtIETable.
func (TAIExtIETable) Table() s00.TAIExtIEsValueExtensionTable {
	return func() s00.TAIExtIEsValueExtensionTable {
		sealed := s00.TAIExtIEsValueExtensionTable{}
		*s00.BridgeTAIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TAIExtIETable.
func (t TAIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TAIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TAIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TAIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TAIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TAIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TAIExtIEsValue {
			sealed := s07.TAIExtIEsValue{}
			*s07.BridgeTAIExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTAIExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTAIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TAIBasedMDTExtIETable struct{}

func TAIBasedMDTExtIEs() TAIBasedMDTExtIETable { return TAIBasedMDTExtIETable{} }

// ID returns the ASN.1 object-set identity of TAIBasedMDTExtIETable.
func (TAIBasedMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAIBasedMDT-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TAIBasedMDTExtIETable.
func (TAIBasedMDTExtIETable) Table() s00.TAIBasedMDTExtIEsValueExtensionTable {
	return func() s00.TAIBasedMDTExtIEsValueExtensionTable {
		sealed := s00.TAIBasedMDTExtIEsValueExtensionTable{}
		*s00.BridgeTAIBasedMDTExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TAIBasedMDTExtIETable.
func (t TAIBasedMDTExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TAIBasedMDTExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TAIBasedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TAIBasedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TAIBasedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TAIBasedMDTExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TAIBasedMDTExtIEsValue {
			sealed := s07.TAIBasedMDTExtIEsValue{}
			*s07.BridgeTAIBasedMDTExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTAIBasedMDTExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTAIBasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TAIBasedQMCExtIETable struct{}

func TAIBasedQMCExtIEs() TAIBasedQMCExtIETable { return TAIBasedQMCExtIETable{} }

// ID returns the ASN.1 object-set identity of TAIBasedQMCExtIETable.
func (TAIBasedQMCExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAIBasedQMC-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TAIBasedQMCExtIETable.
func (TAIBasedQMCExtIETable) Table() s00.TAIBasedQMCExtIEsValueExtensionTable {
	return func() s00.TAIBasedQMCExtIEsValueExtensionTable {
		sealed := s00.TAIBasedQMCExtIEsValueExtensionTable{}
		*s00.BridgeTAIBasedQMCExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TAIBasedQMCExtIETable.
func (t TAIBasedQMCExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TAIBasedQMCExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TAIBasedQMCExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TAIBasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TAIBasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TAIBasedQMCExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TAIBasedQMCExtIEsValue {
			sealed := s07.TAIBasedQMCExtIEsValue{}
			*s07.BridgeTAIBasedQMCExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTAIBasedQMCExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTAIBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TargetNgRanNodeIDExtIETable struct{}

func TargetNgRanNodeIDExtIEs() TargetNgRanNodeIDExtIETable { return TargetNgRanNodeIDExtIETable{} }

// ID returns the ASN.1 object-set identity of TargetNgRanNodeIDExtIETable.
func (TargetNgRanNodeIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargetNgRanNode-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TargetNgRanNodeIDExtIETable.
func (TargetNgRanNodeIDExtIETable) Table() s00.TargetNgRanNodeIDExtIEsValueExtensionTable {
	return func() s00.TargetNgRanNodeIDExtIEsValueExtensionTable {
		sealed := s00.TargetNgRanNodeIDExtIEsValueExtensionTable{}
		*s00.BridgeTargetNgRanNodeIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TargetNgRanNodeIDExtIETable.
func (t TargetNgRanNodeIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TargetNgRanNodeIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TargetNgRanNodeIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TargetNgRanNodeIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TargetNgRanNodeIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TargetNgRanNodeIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TargetNgRanNodeIDExtIEsValue {
			sealed := s07.TargetNgRanNodeIDExtIEsValue{}
			*s07.BridgeTargetNgRanNodeIDExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTargetNgRanNodeIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTargetNgRanNodeIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TargetRNCIDExtIETable struct{}

func TargetRNCIDExtIEs() TargetRNCIDExtIETable { return TargetRNCIDExtIETable{} }

// ID returns the ASN.1 object-set identity of TargetRNCIDExtIETable.
func (TargetRNCIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargetRNC-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TargetRNCIDExtIETable.
func (TargetRNCIDExtIETable) Table() s00.TargetRNCIDExtIEsValueExtensionTable {
	return func() s00.TargetRNCIDExtIEsValueExtensionTable {
		sealed := s00.TargetRNCIDExtIEsValueExtensionTable{}
		*s00.BridgeTargetRNCIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TargetRNCIDExtIETable.
func (t TargetRNCIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TargetRNCIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TargetRNCIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TargetRNCIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TargetRNCIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TargetRNCIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TargetRNCIDExtIEsValue {
			sealed := s07.TargetRNCIDExtIEsValue{}
			*s07.BridgeTargetRNCIDExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTargetRNCIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTargetRNCIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TargeteNBIDExtIETable struct{}

func TargeteNBIDExtIEs() TargeteNBIDExtIETable { return TargeteNBIDExtIETable{} }

// ID returns the ASN.1 object-set identity of TargeteNBIDExtIETable.
func (TargeteNBIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargeteNB-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TargeteNBIDExtIETable.
func (TargeteNBIDExtIETable) Table() s00.TargeteNBIDExtIEsValueExtensionTable {
	return func() s00.TargeteNBIDExtIEsValueExtensionTable {
		sealed := s00.TargeteNBIDExtIEsValueExtensionTable{}
		*s00.BridgeTargeteNBIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TargeteNBIDExtIETable.
func (t TargeteNBIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TargeteNBIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TargeteNBIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TargeteNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TargeteNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TargeteNBIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TargeteNBIDExtIEsValue {
			sealed := s07.TargeteNBIDExtIEsValue{}
			*s07.BridgeTargeteNBIDExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTargeteNBIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTargeteNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TimeBasedHandoverInformationExtIETable struct{}

func TimeBasedHandoverInformationExtIEs() TimeBasedHandoverInformationExtIETable {
	return TimeBasedHandoverInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of TimeBasedHandoverInformationExtIETable.
func (TimeBasedHandoverInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeBasedHandoverInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TimeBasedHandoverInformationExtIETable.
func (TimeBasedHandoverInformationExtIETable) Table() s00.TimeBasedHandoverInformationExtIEsValueExtensionTable {
	return func() s00.TimeBasedHandoverInformationExtIEsValueExtensionTable {
		sealed := s00.TimeBasedHandoverInformationExtIEsValueExtensionTable{}
		*s00.BridgeTimeBasedHandoverInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TimeBasedHandoverInformationExtIETable.
func (t TimeBasedHandoverInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TimeBasedHandoverInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TimeBasedHandoverInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TimeBasedHandoverInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TimeBasedHandoverInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TimeBasedHandoverInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TimeBasedHandoverInformationExtIEsValue {
			sealed := s07.TimeBasedHandoverInformationExtIEsValue{}
			*s07.BridgeTimeBasedHandoverInformationExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTimeBasedHandoverInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTimeBasedHandoverInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TAIItemExtIETable struct{}

func TAIItemExtIEs() TAIItemExtIETable { return TAIItemExtIETable{} }

// ID returns the ASN.1 object-set identity of TAIItemExtIETable.
func (TAIItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TAIItemExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TAIItemExtIETable.
func (TAIItemExtIETable) Table() s00.TAIItemExtIEsValueExtensionTable {
	return func() s00.TAIItemExtIEsValueExtensionTable {
		sealed := s00.TAIItemExtIEsValueExtensionTable{}
		*s00.BridgeTAIItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TAIItemExtIETable.
func (t TAIItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TAIItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TAIItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TAIItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s07.TAIItemExtIEsValue {
			sealed := s07.TAIItemExtIEsValue{}
			*s07.BridgeTAIItemExtIEsValueFieldId(&sealed) = id
			*s07.BridgeTAIItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s07.BridgeTAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// GUMMEITypeCodec binds the complete APER value type.
func GUMMEITypeCodec() s01.GUMMEITypeValueCodec {
	return ServedGUMMEIsItemExtIEs().GUMMEIType().Codec()
}

// RATTypeCodec binds the complete APER value type.
func RATTypeCodec() s01.RATTypeValueCodec { return SupportedTAsItemExtIEs().RATType().Codec() }

// RoutingIDCodec binds the complete APER value type.
func RoutingIDCodec() s02.RoutingIDValueCodec {
	return s09.DownlinkNonUEAssociatedLPPaTransportIEs().RoutingID().Codec()
}

// ThresholdRSRPCodec binds the complete source value type.
func ThresholdRSRPCodec() s02.ThresholdRSRPValueCodec {
	return func() s02.ThresholdRSRPValueCodec {
		sealed := s02.ThresholdRSRPValueCodec{}
		*s02.BridgeThresholdRSRPValueCodecFieldPath(&sealed) = "ThresholdRSRP"
		*s02.BridgeThresholdRSRPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ThresholdRSRP, error) {
			var zero s00.ThresholdRSRP
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ThresholdRSRP, error) {
				var v struct{ Value s00.ThresholdRSRP }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(97), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ThresholdRSRP(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ThresholdRSRP"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeThresholdRSRPValueCodecFieldEncode(&sealed) = func(value s00.ThresholdRSRP, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ThresholdRSRP, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ThresholdRSRP }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(97), false); err != nil {
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
		*s02.BridgeThresholdRSRPValueCodecFieldCapture(&sealed) = func(v s00.ThresholdRSRP, options aper.DecodeState) (s00.ThresholdRSRP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APThresholdRSRP(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeThresholdRSRPValueCodecFieldCompare(&sealed) = func(v s00.ThresholdRSRP, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APThresholdRSRP(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s02.BridgeThresholdRSRPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ThresholdRSRP"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ThresholdRSRQCodec binds the complete source value type.
func ThresholdRSRQCodec() s02.ThresholdRSRQValueCodec {
	return func() s02.ThresholdRSRQValueCodec {
		sealed := s02.ThresholdRSRQValueCodec{}
		*s02.BridgeThresholdRSRQValueCodecFieldPath(&sealed) = "ThresholdRSRQ"
		*s02.BridgeThresholdRSRQValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ThresholdRSRQ, error) {
			var zero s00.ThresholdRSRQ
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ThresholdRSRQ, error) {
				var v struct{ Value s00.ThresholdRSRQ }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(34), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ThresholdRSRQ(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ThresholdRSRQ"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeThresholdRSRQValueCodecFieldEncode(&sealed) = func(value s00.ThresholdRSRQ, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ThresholdRSRQ, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ThresholdRSRQ }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(34), false); err != nil {
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
		*s02.BridgeThresholdRSRQValueCodecFieldCapture(&sealed) = func(v s00.ThresholdRSRQ, options aper.DecodeState) (s00.ThresholdRSRQ, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APThresholdRSRQ(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeThresholdRSRQValueCodecFieldCompare(&sealed) = func(v s00.ThresholdRSRQ, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APThresholdRSRQ(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s02.BridgeThresholdRSRQValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ThresholdRSRQ"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldCapture(v *RequestedTNLInfoExtIEsExtContainerValueCodec) *func(RequestedTNLInfoExtIEsExtContainer, aper.DecodeState) (RequestedTNLInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldCompare(v *RequestedTNLInfoExtIEsExtContainerValueCodec) *func(RequestedTNLInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldContext(v *RequestedTNLInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldDecode(v *RequestedTNLInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RequestedTNLInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldEncode(v *RequestedTNLInfoExtIEsExtContainerValueCodec) *func(RequestedTNLInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestedTNLInfoExtIEsExtContainerValueCodecFieldPath(v *RequestedTNLInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRequestedTNLInfoExtIEsExtFieldFieldReplay(v *RequestedTNLInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRequestedTNLInfoExtIEsExtFieldFieldWithoutReplay(v *RequestedTNLInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRequestedTNLInfoExtIEsExtFieldMethodMarshalAPERTo(v *RequestedTNLInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRequestedTNLInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *RequestedTNLInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldCapture(v *RequestedTNLInfoExtIEsExtFieldValueCodec) *func(RequestedTNLInfoExtIEsExtField, aper.DecodeState) (RequestedTNLInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldCompare(v *RequestedTNLInfoExtIEsExtFieldValueCodec) *func(RequestedTNLInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldContext(v *RequestedTNLInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldDecode(v *RequestedTNLInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RequestedTNLInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldEncode(v *RequestedTNLInfoExtIEsExtFieldValueCodec) *func(RequestedTNLInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestedTNLInfoExtIEsExtFieldValueCodecFieldPath(v *RequestedTNLInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSTMSIExtIEsExtContainerValueCodecFieldCapture(v *STMSIExtIEsExtContainerValueCodec) *func(STMSIExtIEsExtContainer, aper.DecodeState) (STMSIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSTMSIExtIEsExtContainerValueCodecFieldCompare(v *STMSIExtIEsExtContainerValueCodec) *func(STMSIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSTMSIExtIEsExtContainerValueCodecFieldContext(v *STMSIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSTMSIExtIEsExtContainerValueCodecFieldDecode(v *STMSIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (STMSIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSTMSIExtIEsExtContainerValueCodecFieldEncode(v *STMSIExtIEsExtContainerValueCodec) *func(STMSIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSTMSIExtIEsExtContainerValueCodecFieldPath(v *STMSIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSTMSIExtIEsExtFieldFieldReplay(v *STMSIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeSTMSIExtIEsExtFieldFieldWithoutReplay(v *STMSIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSTMSIExtIEsExtFieldMethodMarshalAPERTo(v *STMSIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSTMSIExtIEsExtFieldMethodUnmarshalAPERFrom(v *STMSIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSTMSIExtIEsExtFieldValueCodecFieldCapture(v *STMSIExtIEsExtFieldValueCodec) *func(STMSIExtIEsExtField, aper.DecodeState) (STMSIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSTMSIExtIEsExtFieldValueCodecFieldCompare(v *STMSIExtIEsExtFieldValueCodec) *func(STMSIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSTMSIExtIEsExtFieldValueCodecFieldContext(v *STMSIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSTMSIExtIEsExtFieldValueCodecFieldDecode(v *STMSIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (STMSIExtIEsExtField, error) {
	return &v.decode
}
func BridgeSTMSIExtIEsExtFieldValueCodecFieldEncode(v *STMSIExtIEsExtFieldValueCodec) *func(STMSIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSTMSIExtIEsExtFieldValueCodecFieldPath(v *STMSIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldCapture(v *ScheduledCommunicationTimeExtIEsExtContainerValueCodec) *func(ScheduledCommunicationTimeExtIEsExtContainer, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldCompare(v *ScheduledCommunicationTimeExtIEsExtContainerValueCodec) *func(ScheduledCommunicationTimeExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldContext(v *ScheduledCommunicationTimeExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldDecode(v *ScheduledCommunicationTimeExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldEncode(v *ScheduledCommunicationTimeExtIEsExtContainerValueCodec) *func(ScheduledCommunicationTimeExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldPath(v *ScheduledCommunicationTimeExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldFieldReplay(v *ScheduledCommunicationTimeExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldFieldWithoutReplay(v *ScheduledCommunicationTimeExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldMethodMarshalAPERTo(v *ScheduledCommunicationTimeExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldMethodUnmarshalAPERFrom(v *ScheduledCommunicationTimeExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldCapture(v *ScheduledCommunicationTimeExtIEsExtFieldValueCodec) *func(ScheduledCommunicationTimeExtIEsExtField, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldCompare(v *ScheduledCommunicationTimeExtIEsExtFieldValueCodec) *func(ScheduledCommunicationTimeExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldContext(v *ScheduledCommunicationTimeExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldDecode(v *ScheduledCommunicationTimeExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ScheduledCommunicationTimeExtIEsExtField, error) {
	return &v.decode
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldEncode(v *ScheduledCommunicationTimeExtIEsExtFieldValueCodec) *func(ScheduledCommunicationTimeExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldPath(v *ScheduledCommunicationTimeExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) *func(SecondaryRATDataUsageReportItemExtIEsExtContainer, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) *func(SecondaryRATDataUsageReportItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldContext(v *SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) *func(SecondaryRATDataUsageReportItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldPath(v *SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldFieldReplay(v *SecondaryRATDataUsageReportItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldFieldWithoutReplay(v *SecondaryRATDataUsageReportItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(v *SecondaryRATDataUsageReportItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *SecondaryRATDataUsageReportItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) *func(SecondaryRATDataUsageReportItemExtIEsExtField, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) *func(SecondaryRATDataUsageReportItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldContext(v *SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) *func(SecondaryRATDataUsageReportItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldPath(v *SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityContextExtIEsExtContainerValueCodecFieldCapture(v *SecurityContextExtIEsExtContainerValueCodec) *func(SecurityContextExtIEsExtContainer, aper.DecodeState) (SecurityContextExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityContextExtIEsExtContainerValueCodecFieldCompare(v *SecurityContextExtIEsExtContainerValueCodec) *func(SecurityContextExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityContextExtIEsExtContainerValueCodecFieldContext(v *SecurityContextExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityContextExtIEsExtContainerValueCodecFieldDecode(v *SecurityContextExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SecurityContextExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSecurityContextExtIEsExtContainerValueCodecFieldEncode(v *SecurityContextExtIEsExtContainerValueCodec) *func(SecurityContextExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityContextExtIEsExtContainerValueCodecFieldPath(v *SecurityContextExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityContextExtIEsExtFieldFieldReplay(v *SecurityContextExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSecurityContextExtIEsExtFieldFieldWithoutReplay(v *SecurityContextExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSecurityContextExtIEsExtFieldMethodMarshalAPERTo(v *SecurityContextExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecurityContextExtIEsExtFieldMethodUnmarshalAPERFrom(v *SecurityContextExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecurityContextExtIEsExtFieldValueCodecFieldCapture(v *SecurityContextExtIEsExtFieldValueCodec) *func(SecurityContextExtIEsExtField, aper.DecodeState) (SecurityContextExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityContextExtIEsExtFieldValueCodecFieldCompare(v *SecurityContextExtIEsExtFieldValueCodec) *func(SecurityContextExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityContextExtIEsExtFieldValueCodecFieldContext(v *SecurityContextExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityContextExtIEsExtFieldValueCodecFieldDecode(v *SecurityContextExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SecurityContextExtIEsExtField, error) {
	return &v.decode
}
func BridgeSecurityContextExtIEsExtFieldValueCodecFieldEncode(v *SecurityContextExtIEsExtFieldValueCodec) *func(SecurityContextExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityContextExtIEsExtFieldValueCodecFieldPath(v *SecurityContextExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldCapture(v *SecurityIndicationExtIEsExtContainerValueCodec) *func(SecurityIndicationExtIEsExtContainer, aper.DecodeState) (SecurityIndicationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldCompare(v *SecurityIndicationExtIEsExtContainerValueCodec) *func(SecurityIndicationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldContext(v *SecurityIndicationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldDecode(v *SecurityIndicationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SecurityIndicationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldEncode(v *SecurityIndicationExtIEsExtContainerValueCodec) *func(SecurityIndicationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityIndicationExtIEsExtContainerValueCodecFieldPath(v *SecurityIndicationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityIndicationExtIEsExtFieldFieldReplay(v *SecurityIndicationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSecurityIndicationExtIEsExtFieldFieldWithoutReplay(v *SecurityIndicationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSecurityIndicationExtIEsExtFieldMethodMarshalAPERTo(v *SecurityIndicationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecurityIndicationExtIEsExtFieldMethodUnmarshalAPERFrom(v *SecurityIndicationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldCapture(v *SecurityIndicationExtIEsExtFieldValueCodec) *func(SecurityIndicationExtIEsExtField, aper.DecodeState) (SecurityIndicationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldCompare(v *SecurityIndicationExtIEsExtFieldValueCodec) *func(SecurityIndicationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldContext(v *SecurityIndicationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldDecode(v *SecurityIndicationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SecurityIndicationExtIEsExtField, error) {
	return &v.decode
}
func BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldEncode(v *SecurityIndicationExtIEsExtFieldValueCodec) *func(SecurityIndicationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldPath(v *SecurityIndicationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityResultExtIEsExtContainerValueCodecFieldCapture(v *SecurityResultExtIEsExtContainerValueCodec) *func(SecurityResultExtIEsExtContainer, aper.DecodeState) (SecurityResultExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityResultExtIEsExtContainerValueCodecFieldCompare(v *SecurityResultExtIEsExtContainerValueCodec) *func(SecurityResultExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityResultExtIEsExtContainerValueCodecFieldContext(v *SecurityResultExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityResultExtIEsExtContainerValueCodecFieldDecode(v *SecurityResultExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SecurityResultExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSecurityResultExtIEsExtContainerValueCodecFieldEncode(v *SecurityResultExtIEsExtContainerValueCodec) *func(SecurityResultExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityResultExtIEsExtContainerValueCodecFieldPath(v *SecurityResultExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityResultExtIEsExtFieldFieldReplay(v *SecurityResultExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSecurityResultExtIEsExtFieldFieldWithoutReplay(v *SecurityResultExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSecurityResultExtIEsExtFieldMethodMarshalAPERTo(v *SecurityResultExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecurityResultExtIEsExtFieldMethodUnmarshalAPERFrom(v *SecurityResultExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecurityResultExtIEsExtFieldValueCodecFieldCapture(v *SecurityResultExtIEsExtFieldValueCodec) *func(SecurityResultExtIEsExtField, aper.DecodeState) (SecurityResultExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityResultExtIEsExtFieldValueCodecFieldCompare(v *SecurityResultExtIEsExtFieldValueCodec) *func(SecurityResultExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityResultExtIEsExtFieldValueCodecFieldContext(v *SecurityResultExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityResultExtIEsExtFieldValueCodecFieldDecode(v *SecurityResultExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SecurityResultExtIEsExtField, error) {
	return &v.decode
}
func BridgeSecurityResultExtIEsExtFieldValueCodecFieldEncode(v *SecurityResultExtIEsExtFieldValueCodec) *func(SecurityResultExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityResultExtIEsExtFieldValueCodecFieldPath(v *SecurityResultExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldCapture(v *SensorMeasConfigNameItemExtIEsExtContainerValueCodec) *func(SensorMeasConfigNameItemExtIEsExtContainer, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldCompare(v *SensorMeasConfigNameItemExtIEsExtContainerValueCodec) *func(SensorMeasConfigNameItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldContext(v *SensorMeasConfigNameItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldDecode(v *SensorMeasConfigNameItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldEncode(v *SensorMeasConfigNameItemExtIEsExtContainerValueCodec) *func(SensorMeasConfigNameItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasConfigNameItemExtIEsExtContainerValueCodecFieldPath(v *SensorMeasConfigNameItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldReplay(v *SensorMeasConfigNameItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldFieldWithoutReplay(v *SensorMeasConfigNameItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodMarshalAPERTo(v *SensorMeasConfigNameItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *SensorMeasConfigNameItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldCapture(v *SensorMeasConfigNameItemExtIEsExtFieldValueCodec) *func(SensorMeasConfigNameItemExtIEsExtField, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldCompare(v *SensorMeasConfigNameItemExtIEsExtFieldValueCodec) *func(SensorMeasConfigNameItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldContext(v *SensorMeasConfigNameItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldDecode(v *SensorMeasConfigNameItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SensorMeasConfigNameItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldEncode(v *SensorMeasConfigNameItemExtIEsExtFieldValueCodec) *func(SensorMeasConfigNameItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasConfigNameItemExtIEsExtFieldValueCodecFieldPath(v *SensorMeasConfigNameItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(v *SensorMeasurementConfigurationExtIEsExtContainerValueCodec) *func(SensorMeasurementConfigurationExtIEsExtContainer, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(v *SensorMeasurementConfigurationExtIEsExtContainerValueCodec) *func(SensorMeasurementConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(v *SensorMeasurementConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(v *SensorMeasurementConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(v *SensorMeasurementConfigurationExtIEsExtContainerValueCodec) *func(SensorMeasurementConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasurementConfigurationExtIEsExtContainerValueCodecFieldPath(v *SensorMeasurementConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldReplay(v *SensorMeasurementConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v *SensorMeasurementConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *SensorMeasurementConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *SensorMeasurementConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(v *SensorMeasurementConfigurationExtIEsExtFieldValueCodec) *func(SensorMeasurementConfigurationExtIEsExtField, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(v *SensorMeasurementConfigurationExtIEsExtFieldValueCodec) *func(SensorMeasurementConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(v *SensorMeasurementConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(v *SensorMeasurementConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SensorMeasurementConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(v *SensorMeasurementConfigurationExtIEsExtFieldValueCodec) *func(SensorMeasurementConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasurementConfigurationExtIEsExtFieldValueCodecFieldPath(v *SensorMeasurementConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorNameConfigExtIEContainerValueCodecFieldCapture(v *SensorNameConfigExtIEContainerValueCodec) *func(SensorNameConfigExtIEContainer, aper.DecodeState) (SensorNameConfigExtIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorNameConfigExtIEContainerValueCodecFieldCompare(v *SensorNameConfigExtIEContainerValueCodec) *func(SensorNameConfigExtIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorNameConfigExtIEContainerValueCodecFieldContext(v *SensorNameConfigExtIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigExtIEContainerValueCodecFieldDecode(v *SensorNameConfigExtIEContainerValueCodec) *func([]byte, aper.DecodeState) (SensorNameConfigExtIEContainer, error) {
	return &v.decode
}
func BridgeSensorNameConfigExtIEContainerValueCodecFieldEncode(v *SensorNameConfigExtIEContainerValueCodec) *func(SensorNameConfigExtIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorNameConfigExtIEContainerValueCodecFieldPath(v *SensorNameConfigExtIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorNameConfigExtIEFieldFieldReplay(v *SensorNameConfigExtIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorNameConfigExtIEFieldFieldWithoutReplay(v *SensorNameConfigExtIEField) *bool {
	return &v.withoutReplay
}
func BridgeSensorNameConfigExtIEFieldMethodMarshalAPERTo(v *SensorNameConfigExtIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSensorNameConfigExtIEFieldMethodUnmarshalAPERFrom(v *SensorNameConfigExtIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSensorNameConfigExtIEFieldValueCodecFieldCapture(v *SensorNameConfigExtIEFieldValueCodec) *func(SensorNameConfigExtIEField, aper.DecodeState) (SensorNameConfigExtIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorNameConfigExtIEFieldValueCodecFieldCompare(v *SensorNameConfigExtIEFieldValueCodec) *func(SensorNameConfigExtIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorNameConfigExtIEFieldValueCodecFieldContext(v *SensorNameConfigExtIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigExtIEFieldValueCodecFieldDecode(v *SensorNameConfigExtIEFieldValueCodec) *func([]byte, aper.DecodeState) (SensorNameConfigExtIEField, error) {
	return &v.decode
}
func BridgeSensorNameConfigExtIEFieldValueCodecFieldEncode(v *SensorNameConfigExtIEFieldValueCodec) *func(SensorNameConfigExtIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorNameConfigExtIEFieldValueCodecFieldPath(v *SensorNameConfigExtIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCapture(v *SensorNameConfigExtIEValueERABIEContainerListValueCodec) *func(SensorNameConfigExtIEValueERABIEContainerList, aper.DecodeState) (SensorNameConfigExtIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldCompare(v *SensorNameConfigExtIEValueERABIEContainerListValueCodec) *func(SensorNameConfigExtIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldContext(v *SensorNameConfigExtIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldDecode(v *SensorNameConfigExtIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SensorNameConfigExtIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldEncode(v *SensorNameConfigExtIEValueERABIEContainerListValueCodec) *func(SensorNameConfigExtIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorNameConfigExtIEValueERABIEContainerListValueCodecFieldPath(v *SensorNameConfigExtIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) *func(SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.DecodeState) (SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) *func(SensorNameConfigExtIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SensorNameConfigExtIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) *func(SensorNameConfigExtIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *SensorNameConfigExtIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCapture(v *SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) *func(SensorNameConfigExtIEValueProtocolIEContainerList, aper.DecodeState) (SensorNameConfigExtIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldCompare(v *SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) *func(SensorNameConfigExtIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldContext(v *SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldDecode(v *SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SensorNameConfigExtIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldEncode(v *SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) *func(SensorNameConfigExtIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorNameConfigExtIEValueProtocolIEContainerListValueCodecFieldPath(v *SensorNameConfigExtIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldCapture(v *ServedDCNsItemExtIEsExtContainerValueCodec) *func(ServedDCNsItemExtIEsExtContainer, aper.DecodeState) (ServedDCNsItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldCompare(v *ServedDCNsItemExtIEsExtContainerValueCodec) *func(ServedDCNsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldContext(v *ServedDCNsItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldDecode(v *ServedDCNsItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ServedDCNsItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldEncode(v *ServedDCNsItemExtIEsExtContainerValueCodec) *func(ServedDCNsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedDCNsItemExtIEsExtContainerValueCodecFieldPath(v *ServedDCNsItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeServedDCNsItemExtIEsExtFieldFieldReplay(v *ServedDCNsItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeServedDCNsItemExtIEsExtFieldFieldWithoutReplay(v *ServedDCNsItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeServedDCNsItemExtIEsExtFieldMethodMarshalAPERTo(v *ServedDCNsItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeServedDCNsItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ServedDCNsItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldCapture(v *ServedDCNsItemExtIEsExtFieldValueCodec) *func(ServedDCNsItemExtIEsExtField, aper.DecodeState) (ServedDCNsItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldCompare(v *ServedDCNsItemExtIEsExtFieldValueCodec) *func(ServedDCNsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldContext(v *ServedDCNsItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldDecode(v *ServedDCNsItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ServedDCNsItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldEncode(v *ServedDCNsItemExtIEsExtFieldValueCodec) *func(ServedDCNsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedDCNsItemExtIEsExtFieldValueCodecFieldPath(v *ServedDCNsItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldCapture(v *ServedGUMMEIsItemExtIEsExtContainerValueCodec) *func(ServedGUMMEIsItemExtIEsExtContainer, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldCompare(v *ServedGUMMEIsItemExtIEsExtContainerValueCodec) *func(ServedGUMMEIsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldContext(v *ServedGUMMEIsItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldDecode(v *ServedGUMMEIsItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldEncode(v *ServedGUMMEIsItemExtIEsExtContainerValueCodec) *func(ServedGUMMEIsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedGUMMEIsItemExtIEsExtContainerValueCodecFieldPath(v *ServedGUMMEIsItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeServedGUMMEIsItemExtIEsExtFieldFieldReplay(v *ServedGUMMEIsItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeServedGUMMEIsItemExtIEsExtFieldFieldWithoutReplay(v *ServedGUMMEIsItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeServedGUMMEIsItemExtIEsExtFieldMethodMarshalAPERTo(v *ServedGUMMEIsItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeServedGUMMEIsItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ServedGUMMEIsItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldCapture(v *ServedGUMMEIsItemExtIEsExtFieldValueCodec) *func(ServedGUMMEIsItemExtIEsExtField, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldCompare(v *ServedGUMMEIsItemExtIEsExtFieldValueCodec) *func(ServedGUMMEIsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldContext(v *ServedGUMMEIsItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldDecode(v *ServedGUMMEIsItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ServedGUMMEIsItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldEncode(v *ServedGUMMEIsItemExtIEsExtFieldValueCodec) *func(ServedGUMMEIsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedGUMMEIsItemExtIEsExtFieldValueCodecFieldPath(v *ServedGUMMEIsItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldCapture(v *SourceNgRanNodeIDExtIEsExtContainerValueCodec) *func(SourceNgRanNodeIDExtIEsExtContainer, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldCompare(v *SourceNgRanNodeIDExtIEsExtContainerValueCodec) *func(SourceNgRanNodeIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldContext(v *SourceNgRanNodeIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldDecode(v *SourceNgRanNodeIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldEncode(v *SourceNgRanNodeIDExtIEsExtContainerValueCodec) *func(SourceNgRanNodeIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNgRanNodeIDExtIEsExtContainerValueCodecFieldPath(v *SourceNgRanNodeIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldFieldReplay(v *SourceNgRanNodeIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v *SourceNgRanNodeIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(v *SourceNgRanNodeIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *SourceNgRanNodeIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldCapture(v *SourceNgRanNodeIDExtIEsExtFieldValueCodec) *func(SourceNgRanNodeIDExtIEsExtField, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldCompare(v *SourceNgRanNodeIDExtIEsExtFieldValueCodec) *func(SourceNgRanNodeIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldContext(v *SourceNgRanNodeIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldDecode(v *SourceNgRanNodeIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SourceNgRanNodeIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldEncode(v *SourceNgRanNodeIDExtIEsExtFieldValueCodec) *func(SourceNgRanNodeIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNgRanNodeIDExtIEsExtFieldValueCodecFieldPath(v *SourceNgRanNodeIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldCapture(v *SourceNodeIDExtensionIEIEContainerValueCodec) *func(SourceNodeIDExtensionIEIEContainer, aper.DecodeState) (SourceNodeIDExtensionIEIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldCompare(v *SourceNodeIDExtensionIEIEContainerValueCodec) *func(SourceNodeIDExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldContext(v *SourceNodeIDExtensionIEIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldDecode(v *SourceNodeIDExtensionIEIEContainerValueCodec) *func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEContainer, error) {
	return &v.decode
}
func BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldEncode(v *SourceNodeIDExtensionIEIEContainerValueCodec) *func(SourceNodeIDExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNodeIDExtensionIEIEContainerValueCodecFieldPath(v *SourceNodeIDExtensionIEIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNodeIDExtensionIEIEFieldFieldReplay(v *SourceNodeIDExtensionIEIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceNodeIDExtensionIEIEFieldFieldWithoutReplay(v *SourceNodeIDExtensionIEIEField) *bool {
	return &v.withoutReplay
}
func BridgeSourceNodeIDExtensionIEIEFieldMethodMarshalAPERTo(v *SourceNodeIDExtensionIEIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceNodeIDExtensionIEIEFieldMethodUnmarshalAPERFrom(v *SourceNodeIDExtensionIEIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldCapture(v *SourceNodeIDExtensionIEIEFieldValueCodec) *func(SourceNodeIDExtensionIEIEField, aper.DecodeState) (SourceNodeIDExtensionIEIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldCompare(v *SourceNodeIDExtensionIEIEFieldValueCodec) *func(SourceNodeIDExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldContext(v *SourceNodeIDExtensionIEIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldDecode(v *SourceNodeIDExtensionIEIEFieldValueCodec) *func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEField, error) {
	return &v.decode
}
func BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldEncode(v *SourceNodeIDExtensionIEIEFieldValueCodec) *func(SourceNodeIDExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNodeIDExtensionIEIEFieldValueCodecFieldPath(v *SourceNodeIDExtensionIEIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(v *SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.DecodeState) (SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(v *SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldContext(v *SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(v *SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(v *SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNodeIDExtensionIEIEValueERABIEContainerListValueCodecFieldPath(v *SourceNodeIDExtensionIEIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(v *SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(v *SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(v *SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(v *SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SourceNodeIDExtensionIEIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(v *SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SourceNodeIDExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodecFieldPath(v *SourceNodeIDExtensionIEIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldCapture(v *SourceeNBIDExtIEsExtContainerValueCodec) *func(SourceeNBIDExtIEsExtContainer, aper.DecodeState) (SourceeNBIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldCompare(v *SourceeNBIDExtIEsExtContainerValueCodec) *func(SourceeNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldContext(v *SourceeNBIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldDecode(v *SourceeNBIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SourceeNBIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldEncode(v *SourceeNBIDExtIEsExtContainerValueCodec) *func(SourceeNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceeNBIDExtIEsExtContainerValueCodecFieldPath(v *SourceeNBIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceeNBIDExtIEsExtFieldFieldReplay(v *SourceeNBIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBIDExtIEsExtFieldFieldWithoutReplay(v *SourceeNBIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSourceeNBIDExtIEsExtFieldMethodMarshalAPERTo(v *SourceeNBIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceeNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *SourceeNBIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldCapture(v *SourceeNBIDExtIEsExtFieldValueCodec) *func(SourceeNBIDExtIEsExtField, aper.DecodeState) (SourceeNBIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldCompare(v *SourceeNBIDExtIEsExtFieldValueCodec) *func(SourceeNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldContext(v *SourceeNBIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldDecode(v *SourceeNBIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SourceeNBIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldEncode(v *SourceeNBIDExtIEsExtFieldValueCodec) *func(SourceeNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceeNBIDExtIEsExtFieldValueCodecFieldPath(v *SourceeNBIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCapture(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) *func(SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCompare(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) *func(SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldContext(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldDecode(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldEncode(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) *func(SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldPath(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldReplay(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldFieldWithoutReplay(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldCapture(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) *func(SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldCompare(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) *func(SubscriptionBasedUEDifferentiationInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldContext(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldDecode(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SubscriptionBasedUEDifferentiationInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldEncode(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) *func(SubscriptionBasedUEDifferentiationInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodecFieldPath(v *SubscriptionBasedUEDifferentiationInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldCapture(v *SupportedTAsItemExtIEsExtContainerValueCodec) *func(SupportedTAsItemExtIEsExtContainer, aper.DecodeState) (SupportedTAsItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldCompare(v *SupportedTAsItemExtIEsExtContainerValueCodec) *func(SupportedTAsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldContext(v *SupportedTAsItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldDecode(v *SupportedTAsItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SupportedTAsItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldEncode(v *SupportedTAsItemExtIEsExtContainerValueCodec) *func(SupportedTAsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldPath(v *SupportedTAsItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSupportedTAsItemExtIEsExtFieldFieldReplay(v *SupportedTAsItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSupportedTAsItemExtIEsExtFieldFieldWithoutReplay(v *SupportedTAsItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSupportedTAsItemExtIEsExtFieldMethodMarshalAPERTo(v *SupportedTAsItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSupportedTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *SupportedTAsItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldCapture(v *SupportedTAsItemExtIEsExtFieldValueCodec) *func(SupportedTAsItemExtIEsExtField, aper.DecodeState) (SupportedTAsItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldCompare(v *SupportedTAsItemExtIEsExtFieldValueCodec) *func(SupportedTAsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldContext(v *SupportedTAsItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldDecode(v *SupportedTAsItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SupportedTAsItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldEncode(v *SupportedTAsItemExtIEsExtFieldValueCodec) *func(SupportedTAsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldPath(v *SupportedTAsItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldCapture(v *SynchronisationInformationExtIEsExtContainerValueCodec) *func(SynchronisationInformationExtIEsExtContainer, aper.DecodeState) (SynchronisationInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldCompare(v *SynchronisationInformationExtIEsExtContainerValueCodec) *func(SynchronisationInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldContext(v *SynchronisationInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldDecode(v *SynchronisationInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SynchronisationInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldEncode(v *SynchronisationInformationExtIEsExtContainerValueCodec) *func(SynchronisationInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldPath(v *SynchronisationInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSynchronisationInformationExtIEsExtFieldFieldReplay(v *SynchronisationInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSynchronisationInformationExtIEsExtFieldFieldWithoutReplay(v *SynchronisationInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSynchronisationInformationExtIEsExtFieldMethodMarshalAPERTo(v *SynchronisationInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSynchronisationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *SynchronisationInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldCapture(v *SynchronisationInformationExtIEsExtFieldValueCodec) *func(SynchronisationInformationExtIEsExtField, aper.DecodeState) (SynchronisationInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldCompare(v *SynchronisationInformationExtIEsExtFieldValueCodec) *func(SynchronisationInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldContext(v *SynchronisationInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldDecode(v *SynchronisationInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SynchronisationInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldEncode(v *SynchronisationInformationExtIEsExtFieldValueCodec) *func(SynchronisationInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldPath(v *SynchronisationInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTABasedMDTExtIEsExtContainerValueCodecFieldCapture(v *TABasedMDTExtIEsExtContainerValueCodec) *func(TABasedMDTExtIEsExtContainer, aper.DecodeState) (TABasedMDTExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTABasedMDTExtIEsExtContainerValueCodecFieldCompare(v *TABasedMDTExtIEsExtContainerValueCodec) *func(TABasedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTABasedMDTExtIEsExtContainerValueCodecFieldContext(v *TABasedMDTExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedMDTExtIEsExtContainerValueCodecFieldDecode(v *TABasedMDTExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TABasedMDTExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTABasedMDTExtIEsExtContainerValueCodecFieldEncode(v *TABasedMDTExtIEsExtContainerValueCodec) *func(TABasedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTABasedMDTExtIEsExtContainerValueCodecFieldPath(v *TABasedMDTExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTABasedMDTExtIEsExtFieldFieldReplay(v *TABasedMDTExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTABasedMDTExtIEsExtFieldFieldWithoutReplay(v *TABasedMDTExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTABasedMDTExtIEsExtFieldMethodMarshalAPERTo(v *TABasedMDTExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTABasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(v *TABasedMDTExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTABasedMDTExtIEsExtFieldValueCodecFieldCapture(v *TABasedMDTExtIEsExtFieldValueCodec) *func(TABasedMDTExtIEsExtField, aper.DecodeState) (TABasedMDTExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTABasedMDTExtIEsExtFieldValueCodecFieldCompare(v *TABasedMDTExtIEsExtFieldValueCodec) *func(TABasedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTABasedMDTExtIEsExtFieldValueCodecFieldContext(v *TABasedMDTExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedMDTExtIEsExtFieldValueCodecFieldDecode(v *TABasedMDTExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TABasedMDTExtIEsExtField, error) {
	return &v.decode
}
func BridgeTABasedMDTExtIEsExtFieldValueCodecFieldEncode(v *TABasedMDTExtIEsExtFieldValueCodec) *func(TABasedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTABasedMDTExtIEsExtFieldValueCodecFieldPath(v *TABasedMDTExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTABasedQMCExtIEsExtContainerValueCodecFieldCapture(v *TABasedQMCExtIEsExtContainerValueCodec) *func(TABasedQMCExtIEsExtContainer, aper.DecodeState) (TABasedQMCExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTABasedQMCExtIEsExtContainerValueCodecFieldCompare(v *TABasedQMCExtIEsExtContainerValueCodec) *func(TABasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTABasedQMCExtIEsExtContainerValueCodecFieldContext(v *TABasedQMCExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedQMCExtIEsExtContainerValueCodecFieldDecode(v *TABasedQMCExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TABasedQMCExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTABasedQMCExtIEsExtContainerValueCodecFieldEncode(v *TABasedQMCExtIEsExtContainerValueCodec) *func(TABasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTABasedQMCExtIEsExtContainerValueCodecFieldPath(v *TABasedQMCExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTABasedQMCExtIEsExtFieldFieldReplay(v *TABasedQMCExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTABasedQMCExtIEsExtFieldFieldWithoutReplay(v *TABasedQMCExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTABasedQMCExtIEsExtFieldMethodMarshalAPERTo(v *TABasedQMCExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTABasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(v *TABasedQMCExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTABasedQMCExtIEsExtFieldValueCodecFieldCapture(v *TABasedQMCExtIEsExtFieldValueCodec) *func(TABasedQMCExtIEsExtField, aper.DecodeState) (TABasedQMCExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTABasedQMCExtIEsExtFieldValueCodecFieldCompare(v *TABasedQMCExtIEsExtFieldValueCodec) *func(TABasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTABasedQMCExtIEsExtFieldValueCodecFieldContext(v *TABasedQMCExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedQMCExtIEsExtFieldValueCodecFieldDecode(v *TABasedQMCExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TABasedQMCExtIEsExtField, error) {
	return &v.decode
}
func BridgeTABasedQMCExtIEsExtFieldValueCodecFieldEncode(v *TABasedQMCExtIEsExtFieldValueCodec) *func(TABasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTABasedQMCExtIEsExtFieldValueCodecFieldPath(v *TABasedQMCExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldCapture(v *TAIBasedMDTExtIEsExtContainerValueCodec) *func(TAIBasedMDTExtIEsExtContainer, aper.DecodeState) (TAIBasedMDTExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldCompare(v *TAIBasedMDTExtIEsExtContainerValueCodec) *func(TAIBasedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldContext(v *TAIBasedMDTExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldDecode(v *TAIBasedMDTExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TAIBasedMDTExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldEncode(v *TAIBasedMDTExtIEsExtContainerValueCodec) *func(TAIBasedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldPath(v *TAIBasedMDTExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIBasedMDTExtIEsExtFieldFieldReplay(v *TAIBasedMDTExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIBasedMDTExtIEsExtFieldFieldWithoutReplay(v *TAIBasedMDTExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTAIBasedMDTExtIEsExtFieldMethodMarshalAPERTo(v *TAIBasedMDTExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(v *TAIBasedMDTExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldCapture(v *TAIBasedMDTExtIEsExtFieldValueCodec) *func(TAIBasedMDTExtIEsExtField, aper.DecodeState) (TAIBasedMDTExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldCompare(v *TAIBasedMDTExtIEsExtFieldValueCodec) *func(TAIBasedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldContext(v *TAIBasedMDTExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldDecode(v *TAIBasedMDTExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TAIBasedMDTExtIEsExtField, error) {
	return &v.decode
}
func BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldEncode(v *TAIBasedMDTExtIEsExtFieldValueCodec) *func(TAIBasedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldPath(v *TAIBasedMDTExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldCapture(v *TAIBasedQMCExtIEsExtContainerValueCodec) *func(TAIBasedQMCExtIEsExtContainer, aper.DecodeState) (TAIBasedQMCExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldCompare(v *TAIBasedQMCExtIEsExtContainerValueCodec) *func(TAIBasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldContext(v *TAIBasedQMCExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldDecode(v *TAIBasedQMCExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TAIBasedQMCExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldEncode(v *TAIBasedQMCExtIEsExtContainerValueCodec) *func(TAIBasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldPath(v *TAIBasedQMCExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIBasedQMCExtIEsExtFieldFieldReplay(v *TAIBasedQMCExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIBasedQMCExtIEsExtFieldFieldWithoutReplay(v *TAIBasedQMCExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTAIBasedQMCExtIEsExtFieldMethodMarshalAPERTo(v *TAIBasedQMCExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(v *TAIBasedQMCExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldCapture(v *TAIBasedQMCExtIEsExtFieldValueCodec) *func(TAIBasedQMCExtIEsExtField, aper.DecodeState) (TAIBasedQMCExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldCompare(v *TAIBasedQMCExtIEsExtFieldValueCodec) *func(TAIBasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldContext(v *TAIBasedQMCExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldDecode(v *TAIBasedQMCExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TAIBasedQMCExtIEsExtField, error) {
	return &v.decode
}
func BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldEncode(v *TAIBasedQMCExtIEsExtFieldValueCodec) *func(TAIBasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldPath(v *TAIBasedQMCExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldCapture(v *TAIBroadcastItemExtIEsExtContainerValueCodec) *func(TAIBroadcastItemExtIEsExtContainer, aper.DecodeState) (TAIBroadcastItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldCompare(v *TAIBroadcastItemExtIEsExtContainerValueCodec) *func(TAIBroadcastItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldContext(v *TAIBroadcastItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldDecode(v *TAIBroadcastItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TAIBroadcastItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldEncode(v *TAIBroadcastItemExtIEsExtContainerValueCodec) *func(TAIBroadcastItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldPath(v *TAIBroadcastItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIBroadcastItemExtIEsExtFieldFieldReplay(v *TAIBroadcastItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIBroadcastItemExtIEsExtFieldFieldWithoutReplay(v *TAIBroadcastItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTAIBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(v *TAIBroadcastItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *TAIBroadcastItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldCapture(v *TAIBroadcastItemExtIEsExtFieldValueCodec) *func(TAIBroadcastItemExtIEsExtField, aper.DecodeState) (TAIBroadcastItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldCompare(v *TAIBroadcastItemExtIEsExtFieldValueCodec) *func(TAIBroadcastItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldContext(v *TAIBroadcastItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldDecode(v *TAIBroadcastItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TAIBroadcastItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldEncode(v *TAIBroadcastItemExtIEsExtFieldValueCodec) *func(TAIBroadcastItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldPath(v *TAIBroadcastItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldCapture(v *TAICancelledItemExtIEsExtContainerValueCodec) *func(TAICancelledItemExtIEsExtContainer, aper.DecodeState) (TAICancelledItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldCompare(v *TAICancelledItemExtIEsExtContainerValueCodec) *func(TAICancelledItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldContext(v *TAICancelledItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldDecode(v *TAICancelledItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TAICancelledItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldEncode(v *TAICancelledItemExtIEsExtContainerValueCodec) *func(TAICancelledItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldPath(v *TAICancelledItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAICancelledItemExtIEsExtFieldFieldReplay(v *TAICancelledItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTAICancelledItemExtIEsExtFieldFieldWithoutReplay(v *TAICancelledItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTAICancelledItemExtIEsExtFieldMethodMarshalAPERTo(v *TAICancelledItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAICancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *TAICancelledItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldCapture(v *TAICancelledItemExtIEsExtFieldValueCodec) *func(TAICancelledItemExtIEsExtField, aper.DecodeState) (TAICancelledItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldCompare(v *TAICancelledItemExtIEsExtFieldValueCodec) *func(TAICancelledItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldContext(v *TAICancelledItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldDecode(v *TAICancelledItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TAICancelledItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldEncode(v *TAICancelledItemExtIEsExtFieldValueCodec) *func(TAICancelledItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldPath(v *TAICancelledItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIExtIEsExtContainerValueCodecFieldCapture(v *TAIExtIEsExtContainerValueCodec) *func(TAIExtIEsExtContainer, aper.DecodeState) (TAIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIExtIEsExtContainerValueCodecFieldCompare(v *TAIExtIEsExtContainerValueCodec) *func(TAIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIExtIEsExtContainerValueCodecFieldContext(v *TAIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIExtIEsExtContainerValueCodecFieldDecode(v *TAIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TAIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTAIExtIEsExtContainerValueCodecFieldEncode(v *TAIExtIEsExtContainerValueCodec) *func(TAIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIExtIEsExtContainerValueCodecFieldPath(v *TAIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIExtIEsExtFieldFieldReplay(v *TAIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeTAIExtIEsExtFieldFieldWithoutReplay(v *TAIExtIEsExtField) *bool   { return &v.withoutReplay }
func BridgeTAIExtIEsExtFieldMethodMarshalAPERTo(v *TAIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIExtIEsExtFieldMethodUnmarshalAPERFrom(v *TAIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIExtIEsExtFieldValueCodecFieldCapture(v *TAIExtIEsExtFieldValueCodec) *func(TAIExtIEsExtField, aper.DecodeState) (TAIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIExtIEsExtFieldValueCodecFieldCompare(v *TAIExtIEsExtFieldValueCodec) *func(TAIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIExtIEsExtFieldValueCodecFieldContext(v *TAIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIExtIEsExtFieldValueCodecFieldDecode(v *TAIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TAIExtIEsExtField, error) {
	return &v.decode
}
func BridgeTAIExtIEsExtFieldValueCodecFieldEncode(v *TAIExtIEsExtFieldValueCodec) *func(TAIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIExtIEsExtFieldValueCodecFieldPath(v *TAIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIItemExtIEsExtContainerValueCodecFieldCapture(v *TAIItemExtIEsExtContainerValueCodec) *func(TAIItemExtIEsExtContainer, aper.DecodeState) (TAIItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemExtIEsExtContainerValueCodecFieldCompare(v *TAIItemExtIEsExtContainerValueCodec) *func(TAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemExtIEsExtContainerValueCodecFieldContext(v *TAIItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemExtIEsExtContainerValueCodecFieldDecode(v *TAIItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TAIItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTAIItemExtIEsExtContainerValueCodecFieldEncode(v *TAIItemExtIEsExtContainerValueCodec) *func(TAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemExtIEsExtContainerValueCodecFieldPath(v *TAIItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIItemExtIEsExtFieldFieldReplay(v *TAIItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIItemExtIEsExtFieldFieldWithoutReplay(v *TAIItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTAIItemExtIEsExtFieldMethodMarshalAPERTo(v *TAIItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *TAIItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIItemExtIEsExtFieldValueCodecFieldCapture(v *TAIItemExtIEsExtFieldValueCodec) *func(TAIItemExtIEsExtField, aper.DecodeState) (TAIItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemExtIEsExtFieldValueCodecFieldCompare(v *TAIItemExtIEsExtFieldValueCodec) *func(TAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemExtIEsExtFieldValueCodecFieldContext(v *TAIItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemExtIEsExtFieldValueCodecFieldDecode(v *TAIItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TAIItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeTAIItemExtIEsExtFieldValueCodecFieldEncode(v *TAIItemExtIEsExtFieldValueCodec) *func(TAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemExtIEsExtFieldValueCodecFieldPath(v *TAIItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldCapture(v *TargetNgRanNodeIDExtIEsExtContainerValueCodec) *func(TargetNgRanNodeIDExtIEsExtContainer, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldCompare(v *TargetNgRanNodeIDExtIEsExtContainerValueCodec) *func(TargetNgRanNodeIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldContext(v *TargetNgRanNodeIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldDecode(v *TargetNgRanNodeIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldEncode(v *TargetNgRanNodeIDExtIEsExtContainerValueCodec) *func(TargetNgRanNodeIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldPath(v *TargetNgRanNodeIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldFieldReplay(v *TargetNgRanNodeIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v *TargetNgRanNodeIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(v *TargetNgRanNodeIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *TargetNgRanNodeIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldCapture(v *TargetNgRanNodeIDExtIEsExtFieldValueCodec) *func(TargetNgRanNodeIDExtIEsExtField, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldCompare(v *TargetNgRanNodeIDExtIEsExtFieldValueCodec) *func(TargetNgRanNodeIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldContext(v *TargetNgRanNodeIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldDecode(v *TargetNgRanNodeIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TargetNgRanNodeIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldEncode(v *TargetNgRanNodeIDExtIEsExtFieldValueCodec) *func(TargetNgRanNodeIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldPath(v *TargetNgRanNodeIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldCapture(v *TargetRNCIDExtIEsExtContainerValueCodec) *func(TargetRNCIDExtIEsExtContainer, aper.DecodeState) (TargetRNCIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldCompare(v *TargetRNCIDExtIEsExtContainerValueCodec) *func(TargetRNCIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldContext(v *TargetRNCIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldDecode(v *TargetRNCIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TargetRNCIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldEncode(v *TargetRNCIDExtIEsExtContainerValueCodec) *func(TargetRNCIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldPath(v *TargetRNCIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetRNCIDExtIEsExtFieldFieldReplay(v *TargetRNCIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTargetRNCIDExtIEsExtFieldFieldWithoutReplay(v *TargetRNCIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTargetRNCIDExtIEsExtFieldMethodMarshalAPERTo(v *TargetRNCIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargetRNCIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *TargetRNCIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldCapture(v *TargetRNCIDExtIEsExtFieldValueCodec) *func(TargetRNCIDExtIEsExtField, aper.DecodeState) (TargetRNCIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldCompare(v *TargetRNCIDExtIEsExtFieldValueCodec) *func(TargetRNCIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldContext(v *TargetRNCIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldDecode(v *TargetRNCIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TargetRNCIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldEncode(v *TargetRNCIDExtIEsExtFieldValueCodec) *func(TargetRNCIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldPath(v *TargetRNCIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldCapture(v *TargeteNBIDExtIEsExtContainerValueCodec) *func(TargeteNBIDExtIEsExtContainer, aper.DecodeState) (TargeteNBIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldCompare(v *TargeteNBIDExtIEsExtContainerValueCodec) *func(TargeteNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldContext(v *TargeteNBIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldDecode(v *TargeteNBIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TargeteNBIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldEncode(v *TargeteNBIDExtIEsExtContainerValueCodec) *func(TargeteNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldPath(v *TargeteNBIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargeteNBIDExtIEsExtFieldFieldReplay(v *TargeteNBIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBIDExtIEsExtFieldFieldWithoutReplay(v *TargeteNBIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBIDExtIEsExtFieldMethodMarshalAPERTo(v *TargeteNBIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *TargeteNBIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldCapture(v *TargeteNBIDExtIEsExtFieldValueCodec) *func(TargeteNBIDExtIEsExtField, aper.DecodeState) (TargeteNBIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldCompare(v *TargeteNBIDExtIEsExtFieldValueCodec) *func(TargeteNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldContext(v *TargeteNBIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldDecode(v *TargeteNBIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TargeteNBIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldEncode(v *TargeteNBIDExtIEsExtFieldValueCodec) *func(TargeteNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldPath(v *TargeteNBIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldCapture(v *TimeBasedHandoverInformationExtIEsExtContainerValueCodec) *func(TimeBasedHandoverInformationExtIEsExtContainer, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldCompare(v *TimeBasedHandoverInformationExtIEsExtContainerValueCodec) *func(TimeBasedHandoverInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldContext(v *TimeBasedHandoverInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldDecode(v *TimeBasedHandoverInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldEncode(v *TimeBasedHandoverInformationExtIEsExtContainerValueCodec) *func(TimeBasedHandoverInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldPath(v *TimeBasedHandoverInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldReplay(v *TimeBasedHandoverInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldWithoutReplay(v *TimeBasedHandoverInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodMarshalAPERTo(v *TimeBasedHandoverInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *TimeBasedHandoverInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldCapture(v *TimeBasedHandoverInformationExtIEsExtFieldValueCodec) *func(TimeBasedHandoverInformationExtIEsExtField, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldCompare(v *TimeBasedHandoverInformationExtIEsExtFieldValueCodec) *func(TimeBasedHandoverInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldContext(v *TimeBasedHandoverInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldDecode(v *TimeBasedHandoverInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TimeBasedHandoverInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldEncode(v *TimeBasedHandoverInformationExtIEsExtFieldValueCodec) *func(TimeBasedHandoverInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldPath(v *TimeBasedHandoverInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeSynchronisationInfoExtIEsExtContainerAPERValueFieldContext(v *TimeSynchronisationInfoExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeSynchronisationInfoExtIEsExtContainerAPERValueFieldReceived(v *TimeSynchronisationInfoExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeSynchronisationInfoExtIEsExtContainerAPERValueFieldReplay(v *TimeSynchronisationInfoExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeSynchronisationInfoExtIEsExtContainerAPERValueFieldWithoutReplay(v *TimeSynchronisationInfoExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeSynchronisationInfoExtIEsExtFieldFieldReplay(v *TimeSynchronisationInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeSynchronisationInfoExtIEsExtFieldFieldWithoutReplay(v *TimeSynchronisationInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTimeSynchronisationInfoExtIEsExtFieldMethodMarshalAPERTo(v *TimeSynchronisationInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTimeSynchronisationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *TimeSynchronisationInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
