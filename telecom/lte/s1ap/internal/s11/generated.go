// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s11 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s11

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// MMECPRelocationIndicationIEContainer is ProtocolIE-Container {{MMECPRelocationIndicationIEs}} of TS 36.413: a list of MMECPRelocationIndicationIEField values.
type MMECPRelocationIndicationIEContainer []MMECPRelocationIndicationIEField

// MMECPRelocationIndicationIEField is ProtocolIE-Field {{MMECPRelocationIndicationIEs}} of TS 36.413: an information element field.
type MMECPRelocationIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMECPRelocationIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECPRelocationIndicationIEField) WithoutReplay() MMECPRelocationIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMECPRelocationIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMECPRelocationIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMECPRelocationIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMECPRelocationIndicationIEField{}
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
	var zero MMECPRelocationIndicationIEValue

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

// HandoverSuccessIEContainer is ProtocolIE-Container {{HandoverSuccessIEs}} of TS 36.413: a list of HandoverSuccessIEField values.
type HandoverSuccessIEContainer []HandoverSuccessIEField

// HandoverSuccessIEField is ProtocolIE-Field {{HandoverSuccessIEs}} of TS 36.413: an information element field.
type HandoverSuccessIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverSuccessIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverSuccessIEField) WithoutReplay() HandoverSuccessIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverSuccessIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverSuccessIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverSuccessIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverSuccessIEField{}
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
	var zero HandoverSuccessIEValue

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

// InformationForCECapableUEsExtIEsExtContainer is ProtocolExtensionContainer {{InformationForCECapableUEs-ExtIEs}} of TS 36.413: a list of InformationForCECapableUEsExtIEsExtField values.
type InformationForCECapableUEsExtIEsExtContainer []InformationForCECapableUEsExtIEsExtField

// GERANCellIDExtIEsExtContainer is ProtocolExtensionContainer {{GERAN-Cell-ID-ExtIEs}} of TS 36.413: a list of GERANCellIDExtIEsExtField values.
type GERANCellIDExtIEsExtContainer []GERANCellIDExtIEsExtField

// GlobalENBIDExtIEsExtContainer is ProtocolExtensionContainer {{GlobalENB-ID-ExtIEs}} of TS 36.413: a list of GlobalENBIDExtIEsExtField values.
type GlobalENBIDExtIEsExtContainer []GlobalENBIDExtIEsExtField

// GlobalEnGNBIDExtIEsExtContainer is ProtocolExtensionContainer {{Global-en-gNB-ID-ExtIEs}} of TS 36.413: a list of GlobalEnGNBIDExtIEsExtField values.
type GlobalEnGNBIDExtIEsExtContainer []GlobalEnGNBIDExtIEsExtField

// GBRQosInformationExtIEsExtContainer is ProtocolExtensionContainer {{GBR-QosInformation-ExtIEs}} of TS 36.413: a list of GBRQosInformationExtIEsExtField values.
type GBRQosInformationExtIEsExtContainer []GBRQosInformationExtIEsExtField

// GUMMEIExtIEsExtContainer is ProtocolExtensionContainer {{GUMMEI-ExtIEs}} of TS 36.413: a list of GUMMEIExtIEsExtField values.
type GUMMEIExtIEsExtContainer []GUMMEIExtIEsExtField

// InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer is ProtocolExtensionContainer {{InformationOnRecommendedCellsAndENBsForPaging-ExtIEs}} of TS 36.413: a list of InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField values.
type InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer []InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField

// IntersystemMeasurementConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{IntersystemMeasurementConfiguration-ExtIEs}} of TS 36.413: a list of IntersystemMeasurementConfigurationExtIEsExtField values.
type IntersystemMeasurementConfigurationExtIEsExtContainer []IntersystemMeasurementConfigurationExtIEsExtField

// InterSystemMeasurementParametersExtIEsExtContainer is ProtocolExtensionContainer {{InterSystemMeasurementParameters-ExtIEs}} of TS 36.413: a list of InterSystemMeasurementParametersExtIEsExtField values.
type InterSystemMeasurementParametersExtIEsExtContainer []InterSystemMeasurementParametersExtIEsExtField

// InterSystemMeasurementItemExtIEsExtContainer is ProtocolExtensionContainer {{InterSystemMeasurementItem-ExtIEs}} of TS 36.413: a list of InterSystemMeasurementItemExtIEsExtField values.
type InterSystemMeasurementItemExtIEsExtContainer []InterSystemMeasurementItemExtIEsExtField

// LAIExtIEsExtContainer is ProtocolExtensionContainer {{LAI-ExtIEs}} of TS 36.413: a list of LAIExtIEsExtField values.
type LAIExtIEsExtContainer []LAIExtIEsExtField

// LastVisitedPSCellInformationExtIEsExtContainer is ProtocolExtensionContainer {{LastVisitedPSCellInformation-ExtIEs}} of TS 36.413: a list of LastVisitedPSCellInformationExtIEsExtField values.
type LastVisitedPSCellInformationExtIEsExtContainer []LastVisitedPSCellInformationExtIEsExtField

// ListeningSubframePatternExtIEsExtContainer is ProtocolExtensionContainer {{ListeningSubframePattern-ExtIEs}} of TS 36.413: a list of ListeningSubframePatternExtIEsExtField values.
type ListeningSubframePatternExtIEsExtContainer []ListeningSubframePatternExtIEsExtField

// LoggedMBSFNMDTExtIEsExtContainer is ProtocolExtensionContainer {{LoggedMBSFNMDT-ExtIEs}} of TS 36.413: a list of LoggedMBSFNMDTExtIEsExtField values.
type LoggedMBSFNMDTExtIEsExtContainer []LoggedMBSFNMDTExtIEsExtField

// LTENTNTAIInformationExtIEsExtContainer is ProtocolExtensionContainer {{LTE-NTN-TAI-Information-ExtIEs}} of TS 36.413: a list of LTENTNTAIInformationExtIEsExtField values.
type LTENTNTAIInformationExtIEsExtContainer []LTENTNTAIInformationExtIEsExtField

// M3ConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{M3Configuration-ExtIEs}} of TS 36.413: a list of M3ConfigurationExtIEsExtField values.
type M3ConfigurationExtIEsExtContainer []M3ConfigurationExtIEsExtField

// M4ConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{M4Configuration-ExtIEs}} of TS 36.413: a list of M4ConfigurationExtIEsExtField values.
type M4ConfigurationExtIEsExtContainer []M4ConfigurationExtIEsExtField

// M5ConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{M5Configuration-ExtIEs}} of TS 36.413: a list of M5ConfigurationExtIEsExtField values.
type M5ConfigurationExtIEsExtContainer []M5ConfigurationExtIEsExtField

// M6ConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{M6Configuration-ExtIEs}} of TS 36.413: a list of M6ConfigurationExtIEsExtField values.
type M6ConfigurationExtIEsExtContainer []M6ConfigurationExtIEsExtField

// M7ConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{M7Configuration-ExtIEs}} of TS 36.413: a list of M7ConfigurationExtIEsExtField values.
type M7ConfigurationExtIEsExtContainer []M7ConfigurationExtIEsExtField

// MBSFNResultToLogInfoExtIEsExtContainer is ProtocolExtensionContainer {{MBSFN-ResultToLogInfo-ExtIEs}} of TS 36.413: a list of MBSFNResultToLogInfoExtIEsExtField values.
type MBSFNResultToLogInfoExtIEsExtContainer []MBSFNResultToLogInfoExtIEsExtField

// M1PeriodicReportingExtIEsExtContainer is ProtocolExtensionContainer {{M1PeriodicReporting-ExtIEs}} of TS 36.413: a list of M1PeriodicReportingExtIEsExtField values.
type M1PeriodicReportingExtIEsExtContainer []M1PeriodicReportingExtIEsExtField

// GNBExtIEsExtContainer is ProtocolExtensionContainer {{GNB-ExtIEs}} of TS 36.413: a list of GNBExtIEsExtField values.
type GNBExtIEsExtContainer []GNBExtIEsExtField

// GlobalGNBIDExtIEsExtContainer is ProtocolExtensionContainer {{Global-GNB-ID-ExtIEs}} of TS 36.413: a list of GlobalGNBIDExtIEsExtField values.
type GlobalGNBIDExtIEsExtContainer []GlobalGNBIDExtIEsExtField

// M1ThresholdEventA2ExtIEsExtContainer is ProtocolExtensionContainer {{M1ThresholdEventA2-ExtIEs}} of TS 36.413: a list of M1ThresholdEventA2ExtIEsExtField values.
type M1ThresholdEventA2ExtIEsExtContainer []M1ThresholdEventA2ExtIEsExtField

// InformationForCECapableUEsExtIEsExtField is ProtocolExtensionField {{InformationForCECapableUEs-ExtIEs}} of TS 36.413: an extension field.
type InformationForCECapableUEsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.InformationForCECapableUEsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationForCECapableUEsExtIEsExtField) WithoutReplay() InformationForCECapableUEsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InformationForCECapableUEsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InformationForCECapableUEsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInformationForCECapableUEsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInformationForCECapableUEsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InformationForCECapableUEsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InformationForCECapableUEsExtIEsExtField{}
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
	var zero s05.InformationForCECapableUEsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInformationForCECapableUEsExtIEsValueMethodReason(zero, v.Id), s05.BridgeInformationForCECapableUEsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeInformationForCECapableUEsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GERANCellIDExtIEsExtField is ProtocolExtensionField {{GERAN-Cell-ID-ExtIEs}} of TS 36.413: an extension field.
type GERANCellIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.GERANCellIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GERANCellIDExtIEsExtField) WithoutReplay() GERANCellIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GERANCellIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GERANCellIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGERANCellIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGERANCellIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GERANCellIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GERANCellIDExtIEsExtField{}
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
	var zero s05.GERANCellIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGERANCellIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGERANCellIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeGERANCellIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GlobalENBIDExtIEsExtField is ProtocolExtensionField {{GlobalENB-ID-ExtIEs}} of TS 36.413: an extension field.
type GlobalENBIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.GlobalENBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalENBIDExtIEsExtField) WithoutReplay() GlobalENBIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GlobalENBIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GlobalENBIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGlobalENBIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGlobalENBIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GlobalENBIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalENBIDExtIEsExtField{}
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
	var zero s05.GlobalENBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGlobalENBIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGlobalENBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeGlobalENBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GlobalEnGNBIDExtIEsExtField is ProtocolExtensionField {{Global-en-gNB-ID-ExtIEs}} of TS 36.413: an extension field.
type GlobalEnGNBIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.GlobalEnGNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalEnGNBIDExtIEsExtField) WithoutReplay() GlobalEnGNBIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GlobalEnGNBIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GlobalEnGNBIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGlobalEnGNBIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGlobalEnGNBIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GlobalEnGNBIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalEnGNBIDExtIEsExtField{}
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
	var zero s05.GlobalEnGNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGlobalEnGNBIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGlobalEnGNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeGlobalEnGNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GBRQosInformationExtIEsExtField is ProtocolExtensionField {{GBR-QosInformation-ExtIEs}} of TS 36.413: an extension field.
type GBRQosInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.GBRQosInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GBRQosInformationExtIEsExtField) WithoutReplay() GBRQosInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GBRQosInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GBRQosInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGBRQosInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGBRQosInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GBRQosInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GBRQosInformationExtIEsExtField{}
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
	var zero s05.GBRQosInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGBRQosInformationExtIEsValueMethodReason(zero, v.Id), s05.BridgeGBRQosInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeGBRQosInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GUMMEIExtIEsExtField is ProtocolExtensionField {{GUMMEI-ExtIEs}} of TS 36.413: an extension field.
type GUMMEIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.GUMMEIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GUMMEIExtIEsExtField) WithoutReplay() GUMMEIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GUMMEIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GUMMEIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGUMMEIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGUMMEIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GUMMEIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GUMMEIExtIEsExtField{}
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
	var zero s05.GUMMEIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGUMMEIExtIEsValueMethodReason(zero, v.Id), s05.BridgeGUMMEIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeGUMMEIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField is ProtocolExtensionField {{InformationOnRecommendedCellsAndENBsForPaging-ExtIEs}} of TS 36.413: an extension field.
type InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField) WithoutReplay() InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField{}
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
	var zero s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodReason(zero, v.Id), s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// IntersystemMeasurementConfigurationExtIEsExtField is ProtocolExtensionField {{IntersystemMeasurementConfiguration-ExtIEs}} of TS 36.413: an extension field.
type IntersystemMeasurementConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.IntersystemMeasurementConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntersystemMeasurementConfigurationExtIEsExtField) WithoutReplay() IntersystemMeasurementConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *IntersystemMeasurementConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *IntersystemMeasurementConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *IntersystemMeasurementConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = IntersystemMeasurementConfigurationExtIEsExtField{}
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
	var zero s05.IntersystemMeasurementConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InterSystemMeasurementParametersExtIEsExtField is ProtocolExtensionField {{InterSystemMeasurementParameters-ExtIEs}} of TS 36.413: an extension field.
type InterSystemMeasurementParametersExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.InterSystemMeasurementParametersExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementParametersExtIEsExtField) WithoutReplay() InterSystemMeasurementParametersExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InterSystemMeasurementParametersExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InterSystemMeasurementParametersExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InterSystemMeasurementParametersExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemMeasurementParametersExtIEsExtField{}
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
	var zero s05.InterSystemMeasurementParametersExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodReason(zero, v.Id), s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InterSystemMeasurementItemExtIEsExtField is ProtocolExtensionField {{InterSystemMeasurementItem-ExtIEs}} of TS 36.413: an extension field.
type InterSystemMeasurementItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.InterSystemMeasurementItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementItemExtIEsExtField) WithoutReplay() InterSystemMeasurementItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InterSystemMeasurementItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InterSystemMeasurementItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInterSystemMeasurementItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInterSystemMeasurementItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InterSystemMeasurementItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemMeasurementItemExtIEsExtField{}
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
	var zero s05.InterSystemMeasurementItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInterSystemMeasurementItemExtIEsValueMethodReason(zero, v.Id), s05.BridgeInterSystemMeasurementItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeInterSystemMeasurementItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LAIExtIEsExtField is ProtocolExtensionField {{LAI-ExtIEs}} of TS 36.413: an extension field.
type LAIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.LAIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LAIExtIEsExtField) WithoutReplay() LAIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LAIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LAIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLAIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLAIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LAIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LAIExtIEsExtField{}
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
	var zero s05.LAIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLAIExtIEsValueMethodReason(zero, v.Id), s05.BridgeLAIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeLAIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LastVisitedPSCellInformationExtIEsExtField is ProtocolExtensionField {{LastVisitedPSCellInformation-ExtIEs}} of TS 36.413: an extension field.
type LastVisitedPSCellInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.LastVisitedPSCellInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedPSCellInformationExtIEsExtField) WithoutReplay() LastVisitedPSCellInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LastVisitedPSCellInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LastVisitedPSCellInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LastVisitedPSCellInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedPSCellInformationExtIEsExtField{}
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
	var zero s05.LastVisitedPSCellInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodReason(zero, v.Id), s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ListeningSubframePatternExtIEsExtField is ProtocolExtensionField {{ListeningSubframePattern-ExtIEs}} of TS 36.413: an extension field.
type ListeningSubframePatternExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.ListeningSubframePatternExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ListeningSubframePatternExtIEsExtField) WithoutReplay() ListeningSubframePatternExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ListeningSubframePatternExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ListeningSubframePatternExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeListeningSubframePatternExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeListeningSubframePatternExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ListeningSubframePatternExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ListeningSubframePatternExtIEsExtField{}
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
	var zero s05.ListeningSubframePatternExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeListeningSubframePatternExtIEsValueMethodReason(zero, v.Id), s05.BridgeListeningSubframePatternExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeListeningSubframePatternExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LoggedMBSFNMDTExtIEsExtField is ProtocolExtensionField {{LoggedMBSFNMDT-ExtIEs}} of TS 36.413: an extension field.
type LoggedMBSFNMDTExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.LoggedMBSFNMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMBSFNMDTExtIEsExtField) WithoutReplay() LoggedMBSFNMDTExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LoggedMBSFNMDTExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LoggedMBSFNMDTExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLoggedMBSFNMDTExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLoggedMBSFNMDTExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LoggedMBSFNMDTExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMBSFNMDTExtIEsExtField{}
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
	var zero s05.LoggedMBSFNMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLoggedMBSFNMDTExtIEsValueMethodReason(zero, v.Id), s05.BridgeLoggedMBSFNMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeLoggedMBSFNMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LTENTNTAIInformationExtIEsExtField is ProtocolExtensionField {{LTE-NTN-TAI-Information-ExtIEs}} of TS 36.413: an extension field.
type LTENTNTAIInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.LTENTNTAIInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LTENTNTAIInformationExtIEsExtField) WithoutReplay() LTENTNTAIInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LTENTNTAIInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LTENTNTAIInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLTENTNTAIInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLTENTNTAIInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LTENTNTAIInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LTENTNTAIInformationExtIEsExtField{}
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
	var zero s05.LTENTNTAIInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLTENTNTAIInformationExtIEsValueMethodReason(zero, v.Id), s05.BridgeLTENTNTAIInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeLTENTNTAIInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M3ConfigurationExtIEsExtField is ProtocolExtensionField {{M3Configuration-ExtIEs}} of TS 36.413: an extension field.
type M3ConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.M3ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M3ConfigurationExtIEsExtField) WithoutReplay() M3ConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M3ConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M3ConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM3ConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM3ConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M3ConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M3ConfigurationExtIEsExtField{}
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
	var zero s05.M3ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM3ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM3ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeM3ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M4ConfigurationExtIEsExtField is ProtocolExtensionField {{M4Configuration-ExtIEs}} of TS 36.413: an extension field.
type M4ConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.M4ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M4ConfigurationExtIEsExtField) WithoutReplay() M4ConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M4ConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M4ConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM4ConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM4ConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M4ConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M4ConfigurationExtIEsExtField{}
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
	var zero s05.M4ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM4ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM4ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeM4ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M5ConfigurationExtIEsExtField is ProtocolExtensionField {{M5Configuration-ExtIEs}} of TS 36.413: an extension field.
type M5ConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.M5ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M5ConfigurationExtIEsExtField) WithoutReplay() M5ConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M5ConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M5ConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM5ConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM5ConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M5ConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M5ConfigurationExtIEsExtField{}
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
	var zero s05.M5ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM5ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM5ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeM5ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M6ConfigurationExtIEsExtField is ProtocolExtensionField {{M6Configuration-ExtIEs}} of TS 36.413: an extension field.
type M6ConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.M6ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6ConfigurationExtIEsExtField) WithoutReplay() M6ConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M6ConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M6ConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM6ConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM6ConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M6ConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M6ConfigurationExtIEsExtField{}
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
	var zero s05.M6ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM6ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM6ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeM6ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M7ConfigurationExtIEsExtField is ProtocolExtensionField {{M7Configuration-ExtIEs}} of TS 36.413: an extension field.
type M7ConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.M7ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M7ConfigurationExtIEsExtField) WithoutReplay() M7ConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M7ConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M7ConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM7ConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM7ConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M7ConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M7ConfigurationExtIEsExtField{}
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
	var zero s05.M7ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM7ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM7ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeM7ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MBSFNResultToLogInfoExtIEsExtField is ProtocolExtensionField {{MBSFN-ResultToLogInfo-ExtIEs}} of TS 36.413: an extension field.
type MBSFNResultToLogInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.MBSFNResultToLogInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MBSFNResultToLogInfoExtIEsExtField) WithoutReplay() MBSFNResultToLogInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MBSFNResultToLogInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MBSFNResultToLogInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *MBSFNResultToLogInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MBSFNResultToLogInfoExtIEsExtField{}
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
	var zero s05.MBSFNResultToLogInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodReason(zero, v.Id), s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M1PeriodicReportingExtIEsExtField is ProtocolExtensionField {{M1PeriodicReporting-ExtIEs}} of TS 36.413: an extension field.
type M1PeriodicReportingExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.M1PeriodicReportingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1PeriodicReportingExtIEsExtField) WithoutReplay() M1PeriodicReportingExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M1PeriodicReportingExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M1PeriodicReportingExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM1PeriodicReportingExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM1PeriodicReportingExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M1PeriodicReportingExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M1PeriodicReportingExtIEsExtField{}
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
	var zero s05.M1PeriodicReportingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM1PeriodicReportingExtIEsValueMethodReason(zero, v.Id), s05.BridgeM1PeriodicReportingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeM1PeriodicReportingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GNBExtIEsExtField is ProtocolExtensionField {{GNB-ExtIEs}} of TS 36.413: an extension field.
type GNBExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.GNBExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GNBExtIEsExtField) WithoutReplay() GNBExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GNBExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GNBExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGNBExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGNBExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GNBExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GNBExtIEsExtField{}
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
	var zero s05.GNBExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGNBExtIEsValueMethodReason(zero, v.Id), s05.BridgeGNBExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeGNBExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GlobalGNBIDExtIEsExtField is ProtocolExtensionField {{Global-GNB-ID-ExtIEs}} of TS 36.413: an extension field.
type GlobalGNBIDExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.GlobalGNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalGNBIDExtIEsExtField) WithoutReplay() GlobalGNBIDExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GlobalGNBIDExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GlobalGNBIDExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGlobalGNBIDExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGlobalGNBIDExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GlobalGNBIDExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalGNBIDExtIEsExtField{}
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
	var zero s05.GlobalGNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGlobalGNBIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGlobalGNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeGlobalGNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M1ThresholdEventA2ExtIEsExtField is ProtocolExtensionField {{M1ThresholdEventA2-ExtIEs}} of TS 36.413: an extension field.
type M1ThresholdEventA2ExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s05.M1ThresholdEventA2ExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1ThresholdEventA2ExtIEsExtField) WithoutReplay() M1ThresholdEventA2ExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M1ThresholdEventA2ExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M1ThresholdEventA2ExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM1ThresholdEventA2ExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM1ThresholdEventA2ExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M1ThresholdEventA2ExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M1ThresholdEventA2ExtIEsExtField{}
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
	var zero s05.M1ThresholdEventA2ExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM1ThresholdEventA2ExtIEsValueMethodReason(zero, v.Id), s05.BridgeM1ThresholdEventA2ExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s05.BridgeM1ThresholdEventA2ExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GBRQosInformationExtIEsExtendedBitRateExtBinding binds ExtendedBitRate to the GBR-QosInformation-ExtIEs object set of TS 36.413.
type GBRQosInformationExtIEsExtendedBitRateExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.ExtendedBitRateValueCodec
	inject func(s00.ExtendedBitRate,

	) s05.GBRQosInformationExtIEsValue

	get func(*s05.GBRQosInformationExtIEsValue,

	) (*s00.ExtendedBitRate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b GBRQosInformationExtIEsExtendedBitRateExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b GBRQosInformationExtIEsExtendedBitRateExtBinding) Codec() s00.ExtendedBitRateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b GBRQosInformationExtIEsExtendedBitRateExtBinding) New(value s00.ExtendedBitRate,

) (GBRQosInformationExtIEsExtField, error) {
	if b.inject == nil {
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeExtendedBitRateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return GBRQosInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b GBRQosInformationExtIEsExtendedBitRateExtBinding) Get(field *GBRQosInformationExtIEsExtField) (*s00.ExtendedBitRate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// M4ConfigurationExtIEsM4ReportAmountMDTExtBinding binds M4ReportAmountMDT to the M4Configuration-ExtIEs object set of TS 36.413.
type M4ConfigurationExtIEsM4ReportAmountMDTExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.M4ReportAmountMDTValueCodec
	inject func(s00.M4ReportAmountMDT,

	) s05.M4ConfigurationExtIEsValue

	get func(*s05.M4ConfigurationExtIEsValue,

	) (*s00.M4ReportAmountMDT,

		bool)
}

// Info returns the source descriptor for this binding.
func (b M4ConfigurationExtIEsM4ReportAmountMDTExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b M4ConfigurationExtIEsM4ReportAmountMDTExtBinding) Codec() s01.M4ReportAmountMDTValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b M4ConfigurationExtIEsM4ReportAmountMDTExtBinding) New(value s00.M4ReportAmountMDT,

) (M4ConfigurationExtIEsExtField, error) {
	if b.inject == nil {
		return M4ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M4ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeM4ReportAmountMDTValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return M4ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return M4ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return M4ConfigurationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b M4ConfigurationExtIEsM4ReportAmountMDTExtBinding) Get(field *M4ConfigurationExtIEsExtField) (*s00.M4ReportAmountMDT,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// M5ConfigurationExtIEsM5ReportAmountMDTExtBinding binds M5ReportAmountMDT to the M5Configuration-ExtIEs object set of TS 36.413.
type M5ConfigurationExtIEsM5ReportAmountMDTExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.M5ReportAmountMDTValueCodec
	inject func(s00.M5ReportAmountMDT,

	) s05.M5ConfigurationExtIEsValue

	get func(*s05.M5ConfigurationExtIEsValue,

	) (*s00.M5ReportAmountMDT,

		bool)
}

// Info returns the source descriptor for this binding.
func (b M5ConfigurationExtIEsM5ReportAmountMDTExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b M5ConfigurationExtIEsM5ReportAmountMDTExtBinding) Codec() s01.M5ReportAmountMDTValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b M5ConfigurationExtIEsM5ReportAmountMDTExtBinding) New(value s00.M5ReportAmountMDT,

) (M5ConfigurationExtIEsExtField, error) {
	if b.inject == nil {
		return M5ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M5ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeM5ReportAmountMDTValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return M5ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return M5ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return M5ConfigurationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b M5ConfigurationExtIEsM5ReportAmountMDTExtBinding) Get(field *M5ConfigurationExtIEsExtField) (*s00.M5ReportAmountMDT,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// M6ConfigurationExtIEsM6ReportAmountMDTExtBinding binds M6ReportAmountMDT to the M6Configuration-ExtIEs object set of TS 36.413.
type M6ConfigurationExtIEsM6ReportAmountMDTExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.M6ReportAmountMDTValueCodec
	inject func(s00.M6ReportAmountMDT,

	) s05.M6ConfigurationExtIEsValue

	get func(*s05.M6ConfigurationExtIEsValue,

	) (*s00.M6ReportAmountMDT,

		bool)
}

// Info returns the source descriptor for this binding.
func (b M6ConfigurationExtIEsM6ReportAmountMDTExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b M6ConfigurationExtIEsM6ReportAmountMDTExtBinding) Codec() s01.M6ReportAmountMDTValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b M6ConfigurationExtIEsM6ReportAmountMDTExtBinding) New(value s00.M6ReportAmountMDT,

) (M6ConfigurationExtIEsExtField, error) {
	if b.inject == nil {
		return M6ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M6ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeM6ReportAmountMDTValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return M6ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return M6ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return M6ConfigurationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b M6ConfigurationExtIEsM6ReportAmountMDTExtBinding) Get(field *M6ConfigurationExtIEsExtField) (*s00.M6ReportAmountMDT,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// M7ConfigurationExtIEsM7ReportAmountMDTExtBinding binds M7ReportAmountMDT to the M7Configuration-ExtIEs object set of TS 36.413.
type M7ConfigurationExtIEsM7ReportAmountMDTExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.M7ReportAmountMDTValueCodec
	inject func(s00.M7ReportAmountMDT,

	) s05.M7ConfigurationExtIEsValue

	get func(*s05.M7ConfigurationExtIEsValue,

	) (*s00.M7ReportAmountMDT,

		bool)
}

// Info returns the source descriptor for this binding.
func (b M7ConfigurationExtIEsM7ReportAmountMDTExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b M7ConfigurationExtIEsM7ReportAmountMDTExtBinding) Codec() s01.M7ReportAmountMDTValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b M7ConfigurationExtIEsM7ReportAmountMDTExtBinding) New(value s00.M7ReportAmountMDT,

) (M7ConfigurationExtIEsExtField, error) {
	if b.inject == nil {
		return M7ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M7ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeM7ReportAmountMDTValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return M7ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return M7ConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return M7ConfigurationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b M7ConfigurationExtIEsM7ReportAmountMDTExtBinding) Get(field *M7ConfigurationExtIEsExtField) (*s00.M7ReportAmountMDT,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// HandoverSuccessMMEUES1APIDIEBinding binds MMEUES1APID to the HandoverSuccessIEs object set of TS 36.413.
type HandoverSuccessMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverSuccessIEValue

	get func(*HandoverSuccessIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverSuccessMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverSuccessMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverSuccessMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverSuccessIEField, error) {
	if b.inject == nil {
		return HandoverSuccessIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverSuccessIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverSuccessIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverSuccessIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverSuccessMMEUES1APIDIEBinding) Get(field *HandoverSuccessIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverSuccessENBUES1APIDIEBinding binds ENBUES1APID to the HandoverSuccessIEs object set of TS 36.413.
type HandoverSuccessENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverSuccessIEValue

	get func(*HandoverSuccessIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverSuccessENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverSuccessENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverSuccessENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverSuccessIEField, error) {
	if b.inject == nil {
		return HandoverSuccessIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverSuccessIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverSuccessIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverSuccessIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverSuccessENBUES1APIDIEBinding) Get(field *HandoverSuccessIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMECPRelocationIndicationENBUES1APIDIEBinding binds ENBUES1APID to the MMECPRelocationIndicationIEs object set of TS 36.413.
type MMECPRelocationIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) MMECPRelocationIndicationIEValue

	get func(*MMECPRelocationIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMECPRelocationIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMECPRelocationIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMECPRelocationIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (MMECPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return MMECPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMECPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMECPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMECPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMECPRelocationIndicationENBUES1APIDIEBinding) Get(field *MMECPRelocationIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InformationForCECapableUEsExtIEsIEField uses the ProtocolIE-Field shape for object set InformationForCECapableUEs-ExtIEs of TS 36.413.
type InformationForCECapableUEsExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.InformationForCECapableUEsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationForCECapableUEsExtIEsIEField) WithoutReplay() InformationForCECapableUEsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InformationForCECapableUEsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InformationForCECapableUEsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInformationForCECapableUEsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInformationForCECapableUEsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InformationForCECapableUEsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InformationForCECapableUEsExtIEsIEField{}
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
	var zero s05.InformationForCECapableUEsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInformationForCECapableUEsExtIEsValueMethodReason(zero, v.Id), s05.BridgeInformationForCECapableUEsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeInformationForCECapableUEsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InformationForCECapableUEsExtIEsIEContainer uses the ProtocolIE-Container shape for object set InformationForCECapableUEs-ExtIEs of TS 36.413: a list of InformationForCECapableUEsExtIEsIEField values.
type InformationForCECapableUEsExtIEsIEContainer []InformationForCECapableUEsExtIEsIEField

// GBRQosInformationExtIEsIEField uses the ProtocolIE-Field shape for object set GBR-QosInformation-ExtIEs of TS 36.413.
type GBRQosInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.GBRQosInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GBRQosInformationExtIEsIEField) WithoutReplay() GBRQosInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GBRQosInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GBRQosInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGBRQosInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGBRQosInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GBRQosInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GBRQosInformationExtIEsIEField{}
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
	var zero s05.GBRQosInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGBRQosInformationExtIEsValueMethodReason(zero, v.Id), s05.BridgeGBRQosInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeGBRQosInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GBRQosInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set GBR-QosInformation-ExtIEs of TS 36.413: a list of GBRQosInformationExtIEsIEField values.
type GBRQosInformationExtIEsIEContainer []GBRQosInformationExtIEsIEField

// GERANCellIDExtIEsIEField uses the ProtocolIE-Field shape for object set GERAN-Cell-ID-ExtIEs of TS 36.413.
type GERANCellIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.GERANCellIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GERANCellIDExtIEsIEField) WithoutReplay() GERANCellIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GERANCellIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GERANCellIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGERANCellIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGERANCellIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GERANCellIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GERANCellIDExtIEsIEField{}
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
	var zero s05.GERANCellIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGERANCellIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGERANCellIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeGERANCellIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GERANCellIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set GERAN-Cell-ID-ExtIEs of TS 36.413: a list of GERANCellIDExtIEsIEField values.
type GERANCellIDExtIEsIEContainer []GERANCellIDExtIEsIEField

// GNBExtIEsIEField uses the ProtocolIE-Field shape for object set GNB-ExtIEs of TS 36.413.
type GNBExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.GNBExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GNBExtIEsIEField) WithoutReplay() GNBExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GNBExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GNBExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGNBExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGNBExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GNBExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GNBExtIEsIEField{}
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
	var zero s05.GNBExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGNBExtIEsValueMethodReason(zero, v.Id), s05.BridgeGNBExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeGNBExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GNBExtIEsIEContainer uses the ProtocolIE-Container shape for object set GNB-ExtIEs of TS 36.413: a list of GNBExtIEsIEField values.
type GNBExtIEsIEContainer []GNBExtIEsIEField

// GUMMEIExtIEsIEField uses the ProtocolIE-Field shape for object set GUMMEI-ExtIEs of TS 36.413.
type GUMMEIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.GUMMEIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GUMMEIExtIEsIEField) WithoutReplay() GUMMEIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GUMMEIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GUMMEIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGUMMEIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGUMMEIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GUMMEIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GUMMEIExtIEsIEField{}
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
	var zero s05.GUMMEIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGUMMEIExtIEsValueMethodReason(zero, v.Id), s05.BridgeGUMMEIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeGUMMEIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GUMMEIExtIEsIEContainer uses the ProtocolIE-Container shape for object set GUMMEI-ExtIEs of TS 36.413: a list of GUMMEIExtIEsIEField values.
type GUMMEIExtIEsIEContainer []GUMMEIExtIEsIEField

// GlobalENBIDExtIEsIEField uses the ProtocolIE-Field shape for object set GlobalENB-ID-ExtIEs of TS 36.413.
type GlobalENBIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.GlobalENBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalENBIDExtIEsIEField) WithoutReplay() GlobalENBIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GlobalENBIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GlobalENBIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGlobalENBIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGlobalENBIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GlobalENBIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalENBIDExtIEsIEField{}
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
	var zero s05.GlobalENBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGlobalENBIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGlobalENBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeGlobalENBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GlobalENBIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set GlobalENB-ID-ExtIEs of TS 36.413: a list of GlobalENBIDExtIEsIEField values.
type GlobalENBIDExtIEsIEContainer []GlobalENBIDExtIEsIEField

// GlobalEnGNBIDExtIEsIEField uses the ProtocolIE-Field shape for object set Global-en-gNB-ID-ExtIEs of TS 36.413.
type GlobalEnGNBIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.GlobalEnGNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalEnGNBIDExtIEsIEField) WithoutReplay() GlobalEnGNBIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GlobalEnGNBIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GlobalEnGNBIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGlobalEnGNBIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGlobalEnGNBIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GlobalEnGNBIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalEnGNBIDExtIEsIEField{}
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
	var zero s05.GlobalEnGNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGlobalEnGNBIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGlobalEnGNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeGlobalEnGNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GlobalEnGNBIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set Global-en-gNB-ID-ExtIEs of TS 36.413: a list of GlobalEnGNBIDExtIEsIEField values.
type GlobalEnGNBIDExtIEsIEContainer []GlobalEnGNBIDExtIEsIEField

// GlobalGNBIDExtIEsIEField uses the ProtocolIE-Field shape for object set Global-GNB-ID-ExtIEs of TS 36.413.
type GlobalGNBIDExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.GlobalGNBIDExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalGNBIDExtIEsIEField) WithoutReplay() GlobalGNBIDExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *GlobalGNBIDExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *GlobalGNBIDExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeGlobalGNBIDExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeGlobalGNBIDExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *GlobalGNBIDExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalGNBIDExtIEsIEField{}
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
	var zero s05.GlobalGNBIDExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeGlobalGNBIDExtIEsValueMethodReason(zero, v.Id), s05.BridgeGlobalGNBIDExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeGlobalGNBIDExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// GlobalGNBIDExtIEsIEContainer uses the ProtocolIE-Container shape for object set Global-GNB-ID-ExtIEs of TS 36.413: a list of GlobalGNBIDExtIEsIEField values.
type GlobalGNBIDExtIEsIEContainer []GlobalGNBIDExtIEsIEField

// InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField uses the ProtocolIE-Field shape for object set InformationOnRecommendedCellsAndENBsForPaging-ExtIEs of TS 36.413.
type InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField) WithoutReplay() InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField{}
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
	var zero s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodReason(zero, v.Id), s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsIEContainer uses the ProtocolIE-Container shape for object set InformationOnRecommendedCellsAndENBsForPaging-ExtIEs of TS 36.413: a list of InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField values.
type InformationOnRecommendedCellsAndENBsForPagingExtIEsIEContainer []InformationOnRecommendedCellsAndENBsForPagingExtIEsIEField

// InterSystemMeasurementItemExtIEsIEField uses the ProtocolIE-Field shape for object set InterSystemMeasurementItem-ExtIEs of TS 36.413.
type InterSystemMeasurementItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.InterSystemMeasurementItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementItemExtIEsIEField) WithoutReplay() InterSystemMeasurementItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InterSystemMeasurementItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InterSystemMeasurementItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInterSystemMeasurementItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInterSystemMeasurementItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InterSystemMeasurementItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemMeasurementItemExtIEsIEField{}
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
	var zero s05.InterSystemMeasurementItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInterSystemMeasurementItemExtIEsValueMethodReason(zero, v.Id), s05.BridgeInterSystemMeasurementItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeInterSystemMeasurementItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InterSystemMeasurementItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set InterSystemMeasurementItem-ExtIEs of TS 36.413: a list of InterSystemMeasurementItemExtIEsIEField values.
type InterSystemMeasurementItemExtIEsIEContainer []InterSystemMeasurementItemExtIEsIEField

// InterSystemMeasurementParametersExtIEsIEField uses the ProtocolIE-Field shape for object set InterSystemMeasurementParameters-ExtIEs of TS 36.413.
type InterSystemMeasurementParametersExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.InterSystemMeasurementParametersExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementParametersExtIEsIEField) WithoutReplay() InterSystemMeasurementParametersExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InterSystemMeasurementParametersExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InterSystemMeasurementParametersExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InterSystemMeasurementParametersExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemMeasurementParametersExtIEsIEField{}
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
	var zero s05.InterSystemMeasurementParametersExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodReason(zero, v.Id), s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InterSystemMeasurementParametersExtIEsIEContainer uses the ProtocolIE-Container shape for object set InterSystemMeasurementParameters-ExtIEs of TS 36.413: a list of InterSystemMeasurementParametersExtIEsIEField values.
type InterSystemMeasurementParametersExtIEsIEContainer []InterSystemMeasurementParametersExtIEsIEField

// IntersystemMeasurementConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set IntersystemMeasurementConfiguration-ExtIEs of TS 36.413.
type IntersystemMeasurementConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.IntersystemMeasurementConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntersystemMeasurementConfigurationExtIEsIEField) WithoutReplay() IntersystemMeasurementConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *IntersystemMeasurementConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *IntersystemMeasurementConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *IntersystemMeasurementConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = IntersystemMeasurementConfigurationExtIEsIEField{}
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
	var zero s05.IntersystemMeasurementConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// IntersystemMeasurementConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set IntersystemMeasurementConfiguration-ExtIEs of TS 36.413: a list of IntersystemMeasurementConfigurationExtIEsIEField values.
type IntersystemMeasurementConfigurationExtIEsIEContainer []IntersystemMeasurementConfigurationExtIEsIEField

// LAIExtIEsIEField uses the ProtocolIE-Field shape for object set LAI-ExtIEs of TS 36.413.
type LAIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.LAIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LAIExtIEsIEField) WithoutReplay() LAIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LAIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LAIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLAIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLAIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LAIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LAIExtIEsIEField{}
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
	var zero s05.LAIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLAIExtIEsValueMethodReason(zero, v.Id), s05.BridgeLAIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeLAIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LAIExtIEsIEContainer uses the ProtocolIE-Container shape for object set LAI-ExtIEs of TS 36.413: a list of LAIExtIEsIEField values.
type LAIExtIEsIEContainer []LAIExtIEsIEField

// LTENTNTAIInformationExtIEsIEField uses the ProtocolIE-Field shape for object set LTE-NTN-TAI-Information-ExtIEs of TS 36.413.
type LTENTNTAIInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.LTENTNTAIInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LTENTNTAIInformationExtIEsIEField) WithoutReplay() LTENTNTAIInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LTENTNTAIInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LTENTNTAIInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLTENTNTAIInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLTENTNTAIInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LTENTNTAIInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LTENTNTAIInformationExtIEsIEField{}
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
	var zero s05.LTENTNTAIInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLTENTNTAIInformationExtIEsValueMethodReason(zero, v.Id), s05.BridgeLTENTNTAIInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeLTENTNTAIInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LTENTNTAIInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set LTE-NTN-TAI-Information-ExtIEs of TS 36.413: a list of LTENTNTAIInformationExtIEsIEField values.
type LTENTNTAIInformationExtIEsIEContainer []LTENTNTAIInformationExtIEsIEField

// LastVisitedPSCellInformationExtIEsIEField uses the ProtocolIE-Field shape for object set LastVisitedPSCellInformation-ExtIEs of TS 36.413.
type LastVisitedPSCellInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.LastVisitedPSCellInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedPSCellInformationExtIEsIEField) WithoutReplay() LastVisitedPSCellInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LastVisitedPSCellInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LastVisitedPSCellInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LastVisitedPSCellInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedPSCellInformationExtIEsIEField{}
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
	var zero s05.LastVisitedPSCellInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodReason(zero, v.Id), s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LastVisitedPSCellInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set LastVisitedPSCellInformation-ExtIEs of TS 36.413: a list of LastVisitedPSCellInformationExtIEsIEField values.
type LastVisitedPSCellInformationExtIEsIEContainer []LastVisitedPSCellInformationExtIEsIEField

// ListeningSubframePatternExtIEsIEField uses the ProtocolIE-Field shape for object set ListeningSubframePattern-ExtIEs of TS 36.413.
type ListeningSubframePatternExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.ListeningSubframePatternExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ListeningSubframePatternExtIEsIEField) WithoutReplay() ListeningSubframePatternExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ListeningSubframePatternExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ListeningSubframePatternExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeListeningSubframePatternExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeListeningSubframePatternExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ListeningSubframePatternExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ListeningSubframePatternExtIEsIEField{}
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
	var zero s05.ListeningSubframePatternExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeListeningSubframePatternExtIEsValueMethodReason(zero, v.Id), s05.BridgeListeningSubframePatternExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeListeningSubframePatternExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ListeningSubframePatternExtIEsIEContainer uses the ProtocolIE-Container shape for object set ListeningSubframePattern-ExtIEs of TS 36.413: a list of ListeningSubframePatternExtIEsIEField values.
type ListeningSubframePatternExtIEsIEContainer []ListeningSubframePatternExtIEsIEField

// LoggedMBSFNMDTExtIEsIEField uses the ProtocolIE-Field shape for object set LoggedMBSFNMDT-ExtIEs of TS 36.413.
type LoggedMBSFNMDTExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.LoggedMBSFNMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMBSFNMDTExtIEsIEField) WithoutReplay() LoggedMBSFNMDTExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LoggedMBSFNMDTExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LoggedMBSFNMDTExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeLoggedMBSFNMDTExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeLoggedMBSFNMDTExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *LoggedMBSFNMDTExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMBSFNMDTExtIEsIEField{}
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
	var zero s05.LoggedMBSFNMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeLoggedMBSFNMDTExtIEsValueMethodReason(zero, v.Id), s05.BridgeLoggedMBSFNMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeLoggedMBSFNMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LoggedMBSFNMDTExtIEsIEContainer uses the ProtocolIE-Container shape for object set LoggedMBSFNMDT-ExtIEs of TS 36.413: a list of LoggedMBSFNMDTExtIEsIEField values.
type LoggedMBSFNMDTExtIEsIEContainer []LoggedMBSFNMDTExtIEsIEField

// M1PeriodicReportingExtIEsIEField uses the ProtocolIE-Field shape for object set M1PeriodicReporting-ExtIEs of TS 36.413.
type M1PeriodicReportingExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.M1PeriodicReportingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1PeriodicReportingExtIEsIEField) WithoutReplay() M1PeriodicReportingExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M1PeriodicReportingExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M1PeriodicReportingExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM1PeriodicReportingExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM1PeriodicReportingExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M1PeriodicReportingExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M1PeriodicReportingExtIEsIEField{}
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
	var zero s05.M1PeriodicReportingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM1PeriodicReportingExtIEsValueMethodReason(zero, v.Id), s05.BridgeM1PeriodicReportingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeM1PeriodicReportingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M1PeriodicReportingExtIEsIEContainer uses the ProtocolIE-Container shape for object set M1PeriodicReporting-ExtIEs of TS 36.413: a list of M1PeriodicReportingExtIEsIEField values.
type M1PeriodicReportingExtIEsIEContainer []M1PeriodicReportingExtIEsIEField

// M1ThresholdEventA2ExtIEsIEField uses the ProtocolIE-Field shape for object set M1ThresholdEventA2-ExtIEs of TS 36.413.
type M1ThresholdEventA2ExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.M1ThresholdEventA2ExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1ThresholdEventA2ExtIEsIEField) WithoutReplay() M1ThresholdEventA2ExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M1ThresholdEventA2ExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M1ThresholdEventA2ExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM1ThresholdEventA2ExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM1ThresholdEventA2ExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M1ThresholdEventA2ExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M1ThresholdEventA2ExtIEsIEField{}
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
	var zero s05.M1ThresholdEventA2ExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM1ThresholdEventA2ExtIEsValueMethodReason(zero, v.Id), s05.BridgeM1ThresholdEventA2ExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeM1ThresholdEventA2ExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M1ThresholdEventA2ExtIEsIEContainer uses the ProtocolIE-Container shape for object set M1ThresholdEventA2-ExtIEs of TS 36.413: a list of M1ThresholdEventA2ExtIEsIEField values.
type M1ThresholdEventA2ExtIEsIEContainer []M1ThresholdEventA2ExtIEsIEField

// M3ConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set M3Configuration-ExtIEs of TS 36.413.
type M3ConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.M3ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M3ConfigurationExtIEsIEField) WithoutReplay() M3ConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M3ConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M3ConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM3ConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM3ConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M3ConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M3ConfigurationExtIEsIEField{}
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
	var zero s05.M3ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM3ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM3ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeM3ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M3ConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set M3Configuration-ExtIEs of TS 36.413: a list of M3ConfigurationExtIEsIEField values.
type M3ConfigurationExtIEsIEContainer []M3ConfigurationExtIEsIEField

// M4ConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set M4Configuration-ExtIEs of TS 36.413.
type M4ConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.M4ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M4ConfigurationExtIEsIEField) WithoutReplay() M4ConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M4ConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M4ConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM4ConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM4ConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M4ConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M4ConfigurationExtIEsIEField{}
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
	var zero s05.M4ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM4ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM4ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeM4ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M4ConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set M4Configuration-ExtIEs of TS 36.413: a list of M4ConfigurationExtIEsIEField values.
type M4ConfigurationExtIEsIEContainer []M4ConfigurationExtIEsIEField

// M5ConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set M5Configuration-ExtIEs of TS 36.413.
type M5ConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.M5ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M5ConfigurationExtIEsIEField) WithoutReplay() M5ConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M5ConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M5ConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM5ConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM5ConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M5ConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M5ConfigurationExtIEsIEField{}
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
	var zero s05.M5ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM5ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM5ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeM5ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M5ConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set M5Configuration-ExtIEs of TS 36.413: a list of M5ConfigurationExtIEsIEField values.
type M5ConfigurationExtIEsIEContainer []M5ConfigurationExtIEsIEField

// M6ConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set M6Configuration-ExtIEs of TS 36.413.
type M6ConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.M6ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6ConfigurationExtIEsIEField) WithoutReplay() M6ConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M6ConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M6ConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM6ConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM6ConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M6ConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M6ConfigurationExtIEsIEField{}
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
	var zero s05.M6ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM6ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM6ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeM6ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M6ConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set M6Configuration-ExtIEs of TS 36.413: a list of M6ConfigurationExtIEsIEField values.
type M6ConfigurationExtIEsIEContainer []M6ConfigurationExtIEsIEField

// M7ConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set M7Configuration-ExtIEs of TS 36.413.
type M7ConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.M7ConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M7ConfigurationExtIEsIEField) WithoutReplay() M7ConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *M7ConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *M7ConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeM7ConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeM7ConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *M7ConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M7ConfigurationExtIEsIEField{}
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
	var zero s05.M7ConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeM7ConfigurationExtIEsValueMethodReason(zero, v.Id), s05.BridgeM7ConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeM7ConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// M7ConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set M7Configuration-ExtIEs of TS 36.413: a list of M7ConfigurationExtIEsIEField values.
type M7ConfigurationExtIEsIEContainer []M7ConfigurationExtIEsIEField

// MBSFNResultToLogInfoExtIEsIEField uses the ProtocolIE-Field shape for object set MBSFN-ResultToLogInfo-ExtIEs of TS 36.413.
type MBSFNResultToLogInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s05.MBSFNResultToLogInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MBSFNResultToLogInfoExtIEsIEField) WithoutReplay() MBSFNResultToLogInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MBSFNResultToLogInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MBSFNResultToLogInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *MBSFNResultToLogInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MBSFNResultToLogInfoExtIEsIEField{}
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
	var zero s05.MBSFNResultToLogInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodReason(zero, v.Id), s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MBSFNResultToLogInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set MBSFN-ResultToLogInfo-ExtIEs of TS 36.413: a list of MBSFNResultToLogInfoExtIEsIEField values.
type MBSFNResultToLogInfoExtIEsIEContainer []MBSFNResultToLogInfoExtIEsIEField

// HandoverSuccessIEValueERABIEContainerListValueCodec is the concrete ValueCodec[HandoverSuccessIEValueERABIEContainerList].
type HandoverSuccessIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverSuccessIEValueERABIEContainerList, error)
	encode  func(HandoverSuccessIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverSuccessIEValueERABIEContainerList, aper.DecodeState) (HandoverSuccessIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverSuccessIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverSuccessIEValueERABIEContainerListValueCodec) New(value HandoverSuccessIEValueERABIEContainerList) (HandoverSuccessIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverSuccessIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverSuccessIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverSuccessIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverSuccessIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverSuccessIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverSuccessIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverSuccessIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverSuccessIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverSuccessIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverSuccessIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverSuccessIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverSuccessIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverSuccessIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverSuccessIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverSuccessIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessIEValueERABIEContainerList is E-RAB-IE-ContainerList {{HandoverSuccessIEs}} of TS 36.413: a list of information element fields.
type HandoverSuccessIEValueERABIEContainerList []HandoverSuccessIEValueProtocolIESingleContainer

// GBRQosInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[GBRQosInformationExtIEsExtField].
type GBRQosInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GBRQosInformationExtIEsExtField, error)
	encode  func(GBRQosInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GBRQosInformationExtIEsExtField, aper.DecodeState) (GBRQosInformationExtIEsExtField, aper.Snapshot)
	compare func(GBRQosInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GBRQosInformationExtIEsExtFieldValueCodec) New(value GBRQosInformationExtIEsExtField) (GBRQosInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return GBRQosInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GBRQosInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GBRQosInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GBRQosInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GBRQosInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GBRQosInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GBRQosInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GBRQosInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GBRQosInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GBRQosInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GBRQosInformationExtIEsExtFieldValueCodec) EncodeAPER(value GBRQosInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GBRQosInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value GBRQosInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GBRQosInformationExtIEsExtFieldValueCodec) encodeChanged(value GBRQosInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GERANCellIDExtIEsExtFieldValueCodec is the concrete ValueCodec[GERANCellIDExtIEsExtField].
type GERANCellIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GERANCellIDExtIEsExtField, error)
	encode  func(GERANCellIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GERANCellIDExtIEsExtField, aper.DecodeState) (GERANCellIDExtIEsExtField, aper.Snapshot)
	compare func(GERANCellIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GERANCellIDExtIEsExtFieldValueCodec) New(value GERANCellIDExtIEsExtField) (GERANCellIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return GERANCellIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GERANCellIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GERANCellIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GERANCellIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GERANCellIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GERANCellIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GERANCellIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GERANCellIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GERANCellIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GERANCellIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GERANCellIDExtIEsExtFieldValueCodec) EncodeAPER(value GERANCellIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GERANCellIDExtIEsExtFieldValueCodec) encodeBudgetValue(value GERANCellIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GERANCellIDExtIEsExtFieldValueCodec) encodeChanged(value GERANCellIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GNBExtIEsExtFieldValueCodec is the concrete ValueCodec[GNBExtIEsExtField].
type GNBExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GNBExtIEsExtField, error)
	encode  func(GNBExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GNBExtIEsExtField, aper.DecodeState) (GNBExtIEsExtField, aper.Snapshot)
	compare func(GNBExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GNBExtIEsExtFieldValueCodec) New(value GNBExtIEsExtField) (GNBExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return GNBExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GNBExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GNBExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GNBExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GNBExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GNBExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GNBExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GNBExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GNBExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GNBExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GNBExtIEsExtFieldValueCodec) EncodeAPER(value GNBExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GNBExtIEsExtFieldValueCodec) encodeBudgetValue(value GNBExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GNBExtIEsExtFieldValueCodec) encodeChanged(value GNBExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GUMMEIExtIEsExtFieldValueCodec is the concrete ValueCodec[GUMMEIExtIEsExtField].
type GUMMEIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GUMMEIExtIEsExtField, error)
	encode  func(GUMMEIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GUMMEIExtIEsExtField, aper.DecodeState) (GUMMEIExtIEsExtField, aper.Snapshot)
	compare func(GUMMEIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GUMMEIExtIEsExtFieldValueCodec) New(value GUMMEIExtIEsExtField) (GUMMEIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return GUMMEIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GUMMEIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GUMMEIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GUMMEIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GUMMEIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GUMMEIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GUMMEIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GUMMEIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GUMMEIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GUMMEIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GUMMEIExtIEsExtFieldValueCodec) EncodeAPER(value GUMMEIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GUMMEIExtIEsExtFieldValueCodec) encodeBudgetValue(value GUMMEIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GUMMEIExtIEsExtFieldValueCodec) encodeChanged(value GUMMEIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalENBIDExtIEsExtFieldValueCodec is the concrete ValueCodec[GlobalENBIDExtIEsExtField].
type GlobalENBIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalENBIDExtIEsExtField, error)
	encode  func(GlobalENBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalENBIDExtIEsExtField, aper.DecodeState) (GlobalENBIDExtIEsExtField, aper.Snapshot)
	compare func(GlobalENBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalENBIDExtIEsExtFieldValueCodec) New(value GlobalENBIDExtIEsExtField) (GlobalENBIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return GlobalENBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalENBIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalENBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalENBIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalENBIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalENBIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalENBIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalENBIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalENBIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalENBIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalENBIDExtIEsExtFieldValueCodec) EncodeAPER(value GlobalENBIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GlobalENBIDExtIEsExtFieldValueCodec) encodeBudgetValue(value GlobalENBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalENBIDExtIEsExtFieldValueCodec) encodeChanged(value GlobalENBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalEnGNBIDExtIEsExtFieldValueCodec is the concrete ValueCodec[GlobalEnGNBIDExtIEsExtField].
type GlobalEnGNBIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalEnGNBIDExtIEsExtField, error)
	encode  func(GlobalEnGNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalEnGNBIDExtIEsExtField, aper.DecodeState) (GlobalEnGNBIDExtIEsExtField, aper.Snapshot)
	compare func(GlobalEnGNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalEnGNBIDExtIEsExtFieldValueCodec) New(value GlobalEnGNBIDExtIEsExtField) (GlobalEnGNBIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return GlobalEnGNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalEnGNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalEnGNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalEnGNBIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalEnGNBIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalEnGNBIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalEnGNBIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalEnGNBIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalEnGNBIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalEnGNBIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalEnGNBIDExtIEsExtFieldValueCodec) EncodeAPER(value GlobalEnGNBIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GlobalEnGNBIDExtIEsExtFieldValueCodec) encodeBudgetValue(value GlobalEnGNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalEnGNBIDExtIEsExtFieldValueCodec) encodeChanged(value GlobalEnGNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalGNBIDExtIEsExtFieldValueCodec is the concrete ValueCodec[GlobalGNBIDExtIEsExtField].
type GlobalGNBIDExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalGNBIDExtIEsExtField, error)
	encode  func(GlobalGNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalGNBIDExtIEsExtField, aper.DecodeState) (GlobalGNBIDExtIEsExtField, aper.Snapshot)
	compare func(GlobalGNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalGNBIDExtIEsExtFieldValueCodec) New(value GlobalGNBIDExtIEsExtField) (GlobalGNBIDExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return GlobalGNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalGNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalGNBIDExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalGNBIDExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalGNBIDExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalGNBIDExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalGNBIDExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalGNBIDExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalGNBIDExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalGNBIDExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalGNBIDExtIEsExtFieldValueCodec) EncodeAPER(value GlobalGNBIDExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GlobalGNBIDExtIEsExtFieldValueCodec) encodeBudgetValue(value GlobalGNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalGNBIDExtIEsExtFieldValueCodec) encodeChanged(value GlobalGNBIDExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InformationForCECapableUEsExtIEsExtFieldValueCodec is the concrete ValueCodec[InformationForCECapableUEsExtIEsExtField].
type InformationForCECapableUEsExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InformationForCECapableUEsExtIEsExtField, error)
	encode  func(InformationForCECapableUEsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InformationForCECapableUEsExtIEsExtField, aper.DecodeState) (InformationForCECapableUEsExtIEsExtField, aper.Snapshot)
	compare func(InformationForCECapableUEsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InformationForCECapableUEsExtIEsExtFieldValueCodec) New(value InformationForCECapableUEsExtIEsExtField) (InformationForCECapableUEsExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return InformationForCECapableUEsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InformationForCECapableUEsExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InformationForCECapableUEsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InformationForCECapableUEsExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InformationForCECapableUEsExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InformationForCECapableUEsExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InformationForCECapableUEsExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InformationForCECapableUEsExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InformationForCECapableUEsExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InformationForCECapableUEsExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InformationForCECapableUEsExtIEsExtFieldValueCodec) EncodeAPER(value InformationForCECapableUEsExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InformationForCECapableUEsExtIEsExtFieldValueCodec) encodeBudgetValue(value InformationForCECapableUEsExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InformationForCECapableUEsExtIEsExtFieldValueCodec) encodeChanged(value InformationForCECapableUEsExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec is the concrete ValueCodec[InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField].
type InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, error)
	encode  func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.Snapshot)
	compare func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) New(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) EncodeAPER(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) encodeBudgetValue(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) encodeChanged(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementItemExtIEsExtFieldValueCodec is the concrete ValueCodec[InterSystemMeasurementItemExtIEsExtField].
type InterSystemMeasurementItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtField, error)
	encode  func(InterSystemMeasurementItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementItemExtIEsExtField, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtField, aper.Snapshot)
	compare func(InterSystemMeasurementItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementItemExtIEsExtFieldValueCodec) New(value InterSystemMeasurementItemExtIEsExtField) (InterSystemMeasurementItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementItemExtIEsExtFieldValueCodec) EncodeAPER(value InterSystemMeasurementItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InterSystemMeasurementItemExtIEsExtFieldValueCodec) encodeBudgetValue(value InterSystemMeasurementItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementItemExtIEsExtFieldValueCodec) encodeChanged(value InterSystemMeasurementItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementParametersExtIEsExtFieldValueCodec is the concrete ValueCodec[InterSystemMeasurementParametersExtIEsExtField].
type InterSystemMeasurementParametersExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtField, error)
	encode  func(InterSystemMeasurementParametersExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementParametersExtIEsExtField, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtField, aper.Snapshot)
	compare func(InterSystemMeasurementParametersExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementParametersExtIEsExtFieldValueCodec) New(value InterSystemMeasurementParametersExtIEsExtField) (InterSystemMeasurementParametersExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementParametersExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementParametersExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementParametersExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementParametersExtIEsExtFieldValueCodec) EncodeAPER(value InterSystemMeasurementParametersExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InterSystemMeasurementParametersExtIEsExtFieldValueCodec) encodeBudgetValue(value InterSystemMeasurementParametersExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementParametersExtIEsExtFieldValueCodec) encodeChanged(value InterSystemMeasurementParametersExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[IntersystemMeasurementConfigurationExtIEsExtField].
type IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtField, error)
	encode  func(IntersystemMeasurementConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(IntersystemMeasurementConfigurationExtIEsExtField, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtField, aper.Snapshot)
	compare func(IntersystemMeasurementConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) New(value IntersystemMeasurementConfigurationExtIEsExtField) (IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value IntersystemMeasurementConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) encodeChanged(value IntersystemMeasurementConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LAIExtIEsExtFieldValueCodec is the concrete ValueCodec[LAIExtIEsExtField].
type LAIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LAIExtIEsExtField, error)
	encode  func(LAIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LAIExtIEsExtField, aper.DecodeState) (LAIExtIEsExtField, aper.Snapshot)
	compare func(LAIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LAIExtIEsExtFieldValueCodec) New(value LAIExtIEsExtField) (LAIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return LAIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LAIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LAIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LAIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LAIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LAIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LAIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LAIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LAIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LAIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LAIExtIEsExtFieldValueCodec) EncodeAPER(value LAIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LAIExtIEsExtFieldValueCodec) encodeBudgetValue(value LAIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LAIExtIEsExtFieldValueCodec) encodeChanged(value LAIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LTENTNTAIInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[LTENTNTAIInformationExtIEsExtField].
type LTENTNTAIInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LTENTNTAIInformationExtIEsExtField, error)
	encode  func(LTENTNTAIInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LTENTNTAIInformationExtIEsExtField, aper.DecodeState) (LTENTNTAIInformationExtIEsExtField, aper.Snapshot)
	compare func(LTENTNTAIInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LTENTNTAIInformationExtIEsExtFieldValueCodec) New(value LTENTNTAIInformationExtIEsExtField) (LTENTNTAIInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return LTENTNTAIInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LTENTNTAIInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LTENTNTAIInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LTENTNTAIInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LTENTNTAIInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LTENTNTAIInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LTENTNTAIInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LTENTNTAIInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LTENTNTAIInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LTENTNTAIInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LTENTNTAIInformationExtIEsExtFieldValueCodec) EncodeAPER(value LTENTNTAIInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LTENTNTAIInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value LTENTNTAIInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LTENTNTAIInformationExtIEsExtFieldValueCodec) encodeChanged(value LTENTNTAIInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedPSCellInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[LastVisitedPSCellInformationExtIEsExtField].
type LastVisitedPSCellInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtField, error)
	encode  func(LastVisitedPSCellInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedPSCellInformationExtIEsExtField, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtField, aper.Snapshot)
	compare func(LastVisitedPSCellInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedPSCellInformationExtIEsExtFieldValueCodec) New(value LastVisitedPSCellInformationExtIEsExtField) (LastVisitedPSCellInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedPSCellInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedPSCellInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedPSCellInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedPSCellInformationExtIEsExtFieldValueCodec) EncodeAPER(value LastVisitedPSCellInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LastVisitedPSCellInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value LastVisitedPSCellInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedPSCellInformationExtIEsExtFieldValueCodec) encodeChanged(value LastVisitedPSCellInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ListeningSubframePatternExtIEsExtFieldValueCodec is the concrete ValueCodec[ListeningSubframePatternExtIEsExtField].
type ListeningSubframePatternExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ListeningSubframePatternExtIEsExtField, error)
	encode  func(ListeningSubframePatternExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ListeningSubframePatternExtIEsExtField, aper.DecodeState) (ListeningSubframePatternExtIEsExtField, aper.Snapshot)
	compare func(ListeningSubframePatternExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ListeningSubframePatternExtIEsExtFieldValueCodec) New(value ListeningSubframePatternExtIEsExtField) (ListeningSubframePatternExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ListeningSubframePatternExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ListeningSubframePatternExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ListeningSubframePatternExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ListeningSubframePatternExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ListeningSubframePatternExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ListeningSubframePatternExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ListeningSubframePatternExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ListeningSubframePatternExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ListeningSubframePatternExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ListeningSubframePatternExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ListeningSubframePatternExtIEsExtFieldValueCodec) EncodeAPER(value ListeningSubframePatternExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ListeningSubframePatternExtIEsExtFieldValueCodec) encodeBudgetValue(value ListeningSubframePatternExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ListeningSubframePatternExtIEsExtFieldValueCodec) encodeChanged(value ListeningSubframePatternExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggedMBSFNMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[LoggedMBSFNMDTExtIEsExtField].
type LoggedMBSFNMDTExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtField, error)
	encode  func(LoggedMBSFNMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMBSFNMDTExtIEsExtField, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtField, aper.Snapshot)
	compare func(LoggedMBSFNMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMBSFNMDTExtIEsExtFieldValueCodec) New(value LoggedMBSFNMDTExtIEsExtField) (LoggedMBSFNMDTExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return LoggedMBSFNMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMBSFNMDTExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMBSFNMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMBSFNMDTExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMBSFNMDTExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMBSFNMDTExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMBSFNMDTExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMBSFNMDTExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMBSFNMDTExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMBSFNMDTExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMBSFNMDTExtIEsExtFieldValueCodec) EncodeAPER(value LoggedMBSFNMDTExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LoggedMBSFNMDTExtIEsExtFieldValueCodec) encodeBudgetValue(value LoggedMBSFNMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMBSFNMDTExtIEsExtFieldValueCodec) encodeChanged(value LoggedMBSFNMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M1PeriodicReportingExtIEsExtFieldValueCodec is the concrete ValueCodec[M1PeriodicReportingExtIEsExtField].
type M1PeriodicReportingExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M1PeriodicReportingExtIEsExtField, error)
	encode  func(M1PeriodicReportingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M1PeriodicReportingExtIEsExtField, aper.DecodeState) (M1PeriodicReportingExtIEsExtField, aper.Snapshot)
	compare func(M1PeriodicReportingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M1PeriodicReportingExtIEsExtFieldValueCodec) New(value M1PeriodicReportingExtIEsExtField) (M1PeriodicReportingExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return M1PeriodicReportingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M1PeriodicReportingExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M1PeriodicReportingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M1PeriodicReportingExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M1PeriodicReportingExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M1PeriodicReportingExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M1PeriodicReportingExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M1PeriodicReportingExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M1PeriodicReportingExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M1PeriodicReportingExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M1PeriodicReportingExtIEsExtFieldValueCodec) EncodeAPER(value M1PeriodicReportingExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M1PeriodicReportingExtIEsExtFieldValueCodec) encodeBudgetValue(value M1PeriodicReportingExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M1PeriodicReportingExtIEsExtFieldValueCodec) encodeChanged(value M1PeriodicReportingExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M1ThresholdEventA2ExtIEsExtFieldValueCodec is the concrete ValueCodec[M1ThresholdEventA2ExtIEsExtField].
type M1ThresholdEventA2ExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtField, error)
	encode  func(M1ThresholdEventA2ExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M1ThresholdEventA2ExtIEsExtField, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtField, aper.Snapshot)
	compare func(M1ThresholdEventA2ExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M1ThresholdEventA2ExtIEsExtFieldValueCodec) New(value M1ThresholdEventA2ExtIEsExtField) (M1ThresholdEventA2ExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return M1ThresholdEventA2ExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M1ThresholdEventA2ExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M1ThresholdEventA2ExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M1ThresholdEventA2ExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M1ThresholdEventA2ExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M1ThresholdEventA2ExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M1ThresholdEventA2ExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M1ThresholdEventA2ExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M1ThresholdEventA2ExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M1ThresholdEventA2ExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M1ThresholdEventA2ExtIEsExtFieldValueCodec) EncodeAPER(value M1ThresholdEventA2ExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M1ThresholdEventA2ExtIEsExtFieldValueCodec) encodeBudgetValue(value M1ThresholdEventA2ExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M1ThresholdEventA2ExtIEsExtFieldValueCodec) encodeChanged(value M1ThresholdEventA2ExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M3ConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[M3ConfigurationExtIEsExtField].
type M3ConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M3ConfigurationExtIEsExtField, error)
	encode  func(M3ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M3ConfigurationExtIEsExtField, aper.DecodeState) (M3ConfigurationExtIEsExtField, aper.Snapshot)
	compare func(M3ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M3ConfigurationExtIEsExtFieldValueCodec) New(value M3ConfigurationExtIEsExtField) (M3ConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return M3ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M3ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M3ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M3ConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M3ConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M3ConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M3ConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M3ConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M3ConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M3ConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M3ConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value M3ConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M3ConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value M3ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M3ConfigurationExtIEsExtFieldValueCodec) encodeChanged(value M3ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M4ConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[M4ConfigurationExtIEsExtField].
type M4ConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M4ConfigurationExtIEsExtField, error)
	encode  func(M4ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M4ConfigurationExtIEsExtField, aper.DecodeState) (M4ConfigurationExtIEsExtField, aper.Snapshot)
	compare func(M4ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M4ConfigurationExtIEsExtFieldValueCodec) New(value M4ConfigurationExtIEsExtField) (M4ConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return M4ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M4ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M4ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M4ConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M4ConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M4ConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M4ConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M4ConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M4ConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M4ConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M4ConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value M4ConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M4ConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value M4ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M4ConfigurationExtIEsExtFieldValueCodec) encodeChanged(value M4ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M5ConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[M5ConfigurationExtIEsExtField].
type M5ConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M5ConfigurationExtIEsExtField, error)
	encode  func(M5ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M5ConfigurationExtIEsExtField, aper.DecodeState) (M5ConfigurationExtIEsExtField, aper.Snapshot)
	compare func(M5ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M5ConfigurationExtIEsExtFieldValueCodec) New(value M5ConfigurationExtIEsExtField) (M5ConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return M5ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M5ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M5ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M5ConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M5ConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M5ConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M5ConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M5ConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M5ConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M5ConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M5ConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value M5ConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M5ConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value M5ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M5ConfigurationExtIEsExtFieldValueCodec) encodeChanged(value M5ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M6ConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[M6ConfigurationExtIEsExtField].
type M6ConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M6ConfigurationExtIEsExtField, error)
	encode  func(M6ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M6ConfigurationExtIEsExtField, aper.DecodeState) (M6ConfigurationExtIEsExtField, aper.Snapshot)
	compare func(M6ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M6ConfigurationExtIEsExtFieldValueCodec) New(value M6ConfigurationExtIEsExtField) (M6ConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return M6ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M6ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M6ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M6ConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M6ConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M6ConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M6ConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M6ConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M6ConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M6ConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M6ConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value M6ConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M6ConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value M6ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M6ConfigurationExtIEsExtFieldValueCodec) encodeChanged(value M6ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M7ConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[M7ConfigurationExtIEsExtField].
type M7ConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M7ConfigurationExtIEsExtField, error)
	encode  func(M7ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M7ConfigurationExtIEsExtField, aper.DecodeState) (M7ConfigurationExtIEsExtField, aper.Snapshot)
	compare func(M7ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M7ConfigurationExtIEsExtFieldValueCodec) New(value M7ConfigurationExtIEsExtField) (M7ConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return M7ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M7ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M7ConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M7ConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M7ConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M7ConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M7ConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M7ConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M7ConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M7ConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M7ConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value M7ConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M7ConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value M7ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M7ConfigurationExtIEsExtFieldValueCodec) encodeChanged(value M7ConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MBSFNResultToLogInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[MBSFNResultToLogInfoExtIEsExtField].
type MBSFNResultToLogInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtField, error)
	encode  func(MBSFNResultToLogInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MBSFNResultToLogInfoExtIEsExtField, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtField, aper.Snapshot)
	compare func(MBSFNResultToLogInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MBSFNResultToLogInfoExtIEsExtFieldValueCodec) New(value MBSFNResultToLogInfoExtIEsExtField) (MBSFNResultToLogInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MBSFNResultToLogInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MBSFNResultToLogInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MBSFNResultToLogInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MBSFNResultToLogInfoExtIEsExtFieldValueCodec) EncodeAPER(value MBSFNResultToLogInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MBSFNResultToLogInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value MBSFNResultToLogInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MBSFNResultToLogInfoExtIEsExtFieldValueCodec) encodeChanged(value MBSFNResultToLogInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GBRQosInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[GBRQosInformationExtIEsExtContainer].
type GBRQosInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GBRQosInformationExtIEsExtContainer, error)
	encode  func(GBRQosInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GBRQosInformationExtIEsExtContainer, aper.DecodeState) (GBRQosInformationExtIEsExtContainer, aper.Snapshot)
	compare func(GBRQosInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GBRQosInformationExtIEsExtContainerValueCodec) New(value GBRQosInformationExtIEsExtContainer) (GBRQosInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return GBRQosInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GBRQosInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GBRQosInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GBRQosInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GBRQosInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GBRQosInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GBRQosInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GBRQosInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GBRQosInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GBRQosInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GBRQosInformationExtIEsExtContainerValueCodec) EncodeAPER(value GBRQosInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GBRQosInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value GBRQosInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GBRQosInformationExtIEsExtContainerValueCodec) encodeChanged(value GBRQosInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GERANCellIDExtIEsExtContainerValueCodec is the concrete ValueCodec[GERANCellIDExtIEsExtContainer].
type GERANCellIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GERANCellIDExtIEsExtContainer, error)
	encode  func(GERANCellIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GERANCellIDExtIEsExtContainer, aper.DecodeState) (GERANCellIDExtIEsExtContainer, aper.Snapshot)
	compare func(GERANCellIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GERANCellIDExtIEsExtContainerValueCodec) New(value GERANCellIDExtIEsExtContainer) (GERANCellIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return GERANCellIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GERANCellIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GERANCellIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GERANCellIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GERANCellIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GERANCellIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GERANCellIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GERANCellIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GERANCellIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GERANCellIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GERANCellIDExtIEsExtContainerValueCodec) EncodeAPER(value GERANCellIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GERANCellIDExtIEsExtContainerValueCodec) encodeBudgetValue(value GERANCellIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GERANCellIDExtIEsExtContainerValueCodec) encodeChanged(value GERANCellIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GNBExtIEsExtContainerValueCodec is the concrete ValueCodec[GNBExtIEsExtContainer].
type GNBExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GNBExtIEsExtContainer, error)
	encode  func(GNBExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GNBExtIEsExtContainer, aper.DecodeState) (GNBExtIEsExtContainer, aper.Snapshot)
	compare func(GNBExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GNBExtIEsExtContainerValueCodec) New(value GNBExtIEsExtContainer) (GNBExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return GNBExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GNBExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GNBExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GNBExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GNBExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GNBExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GNBExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GNBExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GNBExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GNBExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GNBExtIEsExtContainerValueCodec) EncodeAPER(value GNBExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GNBExtIEsExtContainerValueCodec) encodeBudgetValue(value GNBExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GNBExtIEsExtContainerValueCodec) encodeChanged(value GNBExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GUMMEIExtIEsExtContainerValueCodec is the concrete ValueCodec[GUMMEIExtIEsExtContainer].
type GUMMEIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GUMMEIExtIEsExtContainer, error)
	encode  func(GUMMEIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GUMMEIExtIEsExtContainer, aper.DecodeState) (GUMMEIExtIEsExtContainer, aper.Snapshot)
	compare func(GUMMEIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GUMMEIExtIEsExtContainerValueCodec) New(value GUMMEIExtIEsExtContainer) (GUMMEIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return GUMMEIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GUMMEIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GUMMEIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GUMMEIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GUMMEIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GUMMEIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GUMMEIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GUMMEIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GUMMEIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GUMMEIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GUMMEIExtIEsExtContainerValueCodec) EncodeAPER(value GUMMEIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GUMMEIExtIEsExtContainerValueCodec) encodeBudgetValue(value GUMMEIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GUMMEIExtIEsExtContainerValueCodec) encodeChanged(value GUMMEIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalENBIDExtIEsExtContainerValueCodec is the concrete ValueCodec[GlobalENBIDExtIEsExtContainer].
type GlobalENBIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalENBIDExtIEsExtContainer, error)
	encode  func(GlobalENBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalENBIDExtIEsExtContainer, aper.DecodeState) (GlobalENBIDExtIEsExtContainer, aper.Snapshot)
	compare func(GlobalENBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalENBIDExtIEsExtContainerValueCodec) New(value GlobalENBIDExtIEsExtContainer) (GlobalENBIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return GlobalENBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalENBIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalENBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalENBIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalENBIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalENBIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalENBIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalENBIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalENBIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalENBIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalENBIDExtIEsExtContainerValueCodec) EncodeAPER(value GlobalENBIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GlobalENBIDExtIEsExtContainerValueCodec) encodeBudgetValue(value GlobalENBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalENBIDExtIEsExtContainerValueCodec) encodeChanged(value GlobalENBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalEnGNBIDExtIEsExtContainerValueCodec is the concrete ValueCodec[GlobalEnGNBIDExtIEsExtContainer].
type GlobalEnGNBIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalEnGNBIDExtIEsExtContainer, error)
	encode  func(GlobalEnGNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalEnGNBIDExtIEsExtContainer, aper.DecodeState) (GlobalEnGNBIDExtIEsExtContainer, aper.Snapshot)
	compare func(GlobalEnGNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalEnGNBIDExtIEsExtContainerValueCodec) New(value GlobalEnGNBIDExtIEsExtContainer) (GlobalEnGNBIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return GlobalEnGNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalEnGNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalEnGNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalEnGNBIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalEnGNBIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalEnGNBIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalEnGNBIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalEnGNBIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalEnGNBIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalEnGNBIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalEnGNBIDExtIEsExtContainerValueCodec) EncodeAPER(value GlobalEnGNBIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GlobalEnGNBIDExtIEsExtContainerValueCodec) encodeBudgetValue(value GlobalEnGNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalEnGNBIDExtIEsExtContainerValueCodec) encodeChanged(value GlobalEnGNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalGNBIDExtIEsExtContainerValueCodec is the concrete ValueCodec[GlobalGNBIDExtIEsExtContainer].
type GlobalGNBIDExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalGNBIDExtIEsExtContainer, error)
	encode  func(GlobalGNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalGNBIDExtIEsExtContainer, aper.DecodeState) (GlobalGNBIDExtIEsExtContainer, aper.Snapshot)
	compare func(GlobalGNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalGNBIDExtIEsExtContainerValueCodec) New(value GlobalGNBIDExtIEsExtContainer) (GlobalGNBIDExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return GlobalGNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalGNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalGNBIDExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalGNBIDExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalGNBIDExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalGNBIDExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalGNBIDExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalGNBIDExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalGNBIDExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalGNBIDExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalGNBIDExtIEsExtContainerValueCodec) EncodeAPER(value GlobalGNBIDExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GlobalGNBIDExtIEsExtContainerValueCodec) encodeBudgetValue(value GlobalGNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalGNBIDExtIEsExtContainerValueCodec) encodeChanged(value GlobalGNBIDExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InformationForCECapableUEsExtIEsExtContainerValueCodec is the concrete ValueCodec[InformationForCECapableUEsExtIEsExtContainer].
type InformationForCECapableUEsExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InformationForCECapableUEsExtIEsExtContainer, error)
	encode  func(InformationForCECapableUEsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InformationForCECapableUEsExtIEsExtContainer, aper.DecodeState) (InformationForCECapableUEsExtIEsExtContainer, aper.Snapshot)
	compare func(InformationForCECapableUEsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InformationForCECapableUEsExtIEsExtContainerValueCodec) New(value InformationForCECapableUEsExtIEsExtContainer) (InformationForCECapableUEsExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return InformationForCECapableUEsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InformationForCECapableUEsExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InformationForCECapableUEsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InformationForCECapableUEsExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InformationForCECapableUEsExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InformationForCECapableUEsExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InformationForCECapableUEsExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InformationForCECapableUEsExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InformationForCECapableUEsExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InformationForCECapableUEsExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InformationForCECapableUEsExtIEsExtContainerValueCodec) EncodeAPER(value InformationForCECapableUEsExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InformationForCECapableUEsExtIEsExtContainerValueCodec) encodeBudgetValue(value InformationForCECapableUEsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InformationForCECapableUEsExtIEsExtContainerValueCodec) encodeChanged(value InformationForCECapableUEsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec is the concrete ValueCodec[InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer].
type InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, error)
	encode  func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.Snapshot)
	compare func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) New(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) EncodeAPER(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) encodeBudgetValue(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) encodeChanged(value InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementItemExtIEsExtContainerValueCodec is the concrete ValueCodec[InterSystemMeasurementItemExtIEsExtContainer].
type InterSystemMeasurementItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtContainer, error)
	encode  func(InterSystemMeasurementItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementItemExtIEsExtContainer, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtContainer, aper.Snapshot)
	compare func(InterSystemMeasurementItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementItemExtIEsExtContainerValueCodec) New(value InterSystemMeasurementItemExtIEsExtContainer) (InterSystemMeasurementItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementItemExtIEsExtContainerValueCodec) EncodeAPER(value InterSystemMeasurementItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InterSystemMeasurementItemExtIEsExtContainerValueCodec) encodeBudgetValue(value InterSystemMeasurementItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementItemExtIEsExtContainerValueCodec) encodeChanged(value InterSystemMeasurementItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementParametersExtIEsExtContainerValueCodec is the concrete ValueCodec[InterSystemMeasurementParametersExtIEsExtContainer].
type InterSystemMeasurementParametersExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtContainer, error)
	encode  func(InterSystemMeasurementParametersExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementParametersExtIEsExtContainer, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtContainer, aper.Snapshot)
	compare func(InterSystemMeasurementParametersExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementParametersExtIEsExtContainerValueCodec) New(value InterSystemMeasurementParametersExtIEsExtContainer) (InterSystemMeasurementParametersExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementParametersExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementParametersExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementParametersExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementParametersExtIEsExtContainerValueCodec) EncodeAPER(value InterSystemMeasurementParametersExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InterSystemMeasurementParametersExtIEsExtContainerValueCodec) encodeBudgetValue(value InterSystemMeasurementParametersExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementParametersExtIEsExtContainerValueCodec) encodeChanged(value InterSystemMeasurementParametersExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[IntersystemMeasurementConfigurationExtIEsExtContainer].
type IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtContainer, error)
	encode  func(IntersystemMeasurementConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(IntersystemMeasurementConfigurationExtIEsExtContainer, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(IntersystemMeasurementConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) New(value IntersystemMeasurementConfigurationExtIEsExtContainer) (IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value IntersystemMeasurementConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) encodeChanged(value IntersystemMeasurementConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LAIExtIEsExtContainerValueCodec is the concrete ValueCodec[LAIExtIEsExtContainer].
type LAIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LAIExtIEsExtContainer, error)
	encode  func(LAIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LAIExtIEsExtContainer, aper.DecodeState) (LAIExtIEsExtContainer, aper.Snapshot)
	compare func(LAIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LAIExtIEsExtContainerValueCodec) New(value LAIExtIEsExtContainer) (LAIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return LAIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LAIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LAIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LAIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LAIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LAIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LAIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LAIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LAIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LAIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LAIExtIEsExtContainerValueCodec) EncodeAPER(value LAIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LAIExtIEsExtContainerValueCodec) encodeBudgetValue(value LAIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LAIExtIEsExtContainerValueCodec) encodeChanged(value LAIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LTENTNTAIInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[LTENTNTAIInformationExtIEsExtContainer].
type LTENTNTAIInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LTENTNTAIInformationExtIEsExtContainer, error)
	encode  func(LTENTNTAIInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LTENTNTAIInformationExtIEsExtContainer, aper.DecodeState) (LTENTNTAIInformationExtIEsExtContainer, aper.Snapshot)
	compare func(LTENTNTAIInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LTENTNTAIInformationExtIEsExtContainerValueCodec) New(value LTENTNTAIInformationExtIEsExtContainer) (LTENTNTAIInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return LTENTNTAIInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LTENTNTAIInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LTENTNTAIInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LTENTNTAIInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LTENTNTAIInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LTENTNTAIInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LTENTNTAIInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LTENTNTAIInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LTENTNTAIInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LTENTNTAIInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LTENTNTAIInformationExtIEsExtContainerValueCodec) EncodeAPER(value LTENTNTAIInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LTENTNTAIInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value LTENTNTAIInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LTENTNTAIInformationExtIEsExtContainerValueCodec) encodeChanged(value LTENTNTAIInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedPSCellInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[LastVisitedPSCellInformationExtIEsExtContainer].
type LastVisitedPSCellInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtContainer, error)
	encode  func(LastVisitedPSCellInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedPSCellInformationExtIEsExtContainer, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtContainer, aper.Snapshot)
	compare func(LastVisitedPSCellInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedPSCellInformationExtIEsExtContainerValueCodec) New(value LastVisitedPSCellInformationExtIEsExtContainer) (LastVisitedPSCellInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedPSCellInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedPSCellInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedPSCellInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedPSCellInformationExtIEsExtContainerValueCodec) EncodeAPER(value LastVisitedPSCellInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LastVisitedPSCellInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value LastVisitedPSCellInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedPSCellInformationExtIEsExtContainerValueCodec) encodeChanged(value LastVisitedPSCellInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ListeningSubframePatternExtIEsExtContainerValueCodec is the concrete ValueCodec[ListeningSubframePatternExtIEsExtContainer].
type ListeningSubframePatternExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ListeningSubframePatternExtIEsExtContainer, error)
	encode  func(ListeningSubframePatternExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ListeningSubframePatternExtIEsExtContainer, aper.DecodeState) (ListeningSubframePatternExtIEsExtContainer, aper.Snapshot)
	compare func(ListeningSubframePatternExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ListeningSubframePatternExtIEsExtContainerValueCodec) New(value ListeningSubframePatternExtIEsExtContainer) (ListeningSubframePatternExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ListeningSubframePatternExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ListeningSubframePatternExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ListeningSubframePatternExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ListeningSubframePatternExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ListeningSubframePatternExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ListeningSubframePatternExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ListeningSubframePatternExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ListeningSubframePatternExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ListeningSubframePatternExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ListeningSubframePatternExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ListeningSubframePatternExtIEsExtContainerValueCodec) EncodeAPER(value ListeningSubframePatternExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ListeningSubframePatternExtIEsExtContainerValueCodec) encodeBudgetValue(value ListeningSubframePatternExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ListeningSubframePatternExtIEsExtContainerValueCodec) encodeChanged(value ListeningSubframePatternExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggedMBSFNMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[LoggedMBSFNMDTExtIEsExtContainer].
type LoggedMBSFNMDTExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtContainer, error)
	encode  func(LoggedMBSFNMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMBSFNMDTExtIEsExtContainer, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtContainer, aper.Snapshot)
	compare func(LoggedMBSFNMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMBSFNMDTExtIEsExtContainerValueCodec) New(value LoggedMBSFNMDTExtIEsExtContainer) (LoggedMBSFNMDTExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return LoggedMBSFNMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMBSFNMDTExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMBSFNMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMBSFNMDTExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMBSFNMDTExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMBSFNMDTExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMBSFNMDTExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMBSFNMDTExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMBSFNMDTExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMBSFNMDTExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMBSFNMDTExtIEsExtContainerValueCodec) EncodeAPER(value LoggedMBSFNMDTExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LoggedMBSFNMDTExtIEsExtContainerValueCodec) encodeBudgetValue(value LoggedMBSFNMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMBSFNMDTExtIEsExtContainerValueCodec) encodeChanged(value LoggedMBSFNMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M1PeriodicReportingExtIEsExtContainerValueCodec is the concrete ValueCodec[M1PeriodicReportingExtIEsExtContainer].
type M1PeriodicReportingExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M1PeriodicReportingExtIEsExtContainer, error)
	encode  func(M1PeriodicReportingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M1PeriodicReportingExtIEsExtContainer, aper.DecodeState) (M1PeriodicReportingExtIEsExtContainer, aper.Snapshot)
	compare func(M1PeriodicReportingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M1PeriodicReportingExtIEsExtContainerValueCodec) New(value M1PeriodicReportingExtIEsExtContainer) (M1PeriodicReportingExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return M1PeriodicReportingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M1PeriodicReportingExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M1PeriodicReportingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M1PeriodicReportingExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M1PeriodicReportingExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M1PeriodicReportingExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M1PeriodicReportingExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M1PeriodicReportingExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M1PeriodicReportingExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M1PeriodicReportingExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M1PeriodicReportingExtIEsExtContainerValueCodec) EncodeAPER(value M1PeriodicReportingExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M1PeriodicReportingExtIEsExtContainerValueCodec) encodeBudgetValue(value M1PeriodicReportingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M1PeriodicReportingExtIEsExtContainerValueCodec) encodeChanged(value M1PeriodicReportingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M1ThresholdEventA2ExtIEsExtContainerValueCodec is the concrete ValueCodec[M1ThresholdEventA2ExtIEsExtContainer].
type M1ThresholdEventA2ExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtContainer, error)
	encode  func(M1ThresholdEventA2ExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M1ThresholdEventA2ExtIEsExtContainer, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtContainer, aper.Snapshot)
	compare func(M1ThresholdEventA2ExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M1ThresholdEventA2ExtIEsExtContainerValueCodec) New(value M1ThresholdEventA2ExtIEsExtContainer) (M1ThresholdEventA2ExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return M1ThresholdEventA2ExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M1ThresholdEventA2ExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M1ThresholdEventA2ExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M1ThresholdEventA2ExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M1ThresholdEventA2ExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M1ThresholdEventA2ExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M1ThresholdEventA2ExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M1ThresholdEventA2ExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M1ThresholdEventA2ExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M1ThresholdEventA2ExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M1ThresholdEventA2ExtIEsExtContainerValueCodec) EncodeAPER(value M1ThresholdEventA2ExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M1ThresholdEventA2ExtIEsExtContainerValueCodec) encodeBudgetValue(value M1ThresholdEventA2ExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M1ThresholdEventA2ExtIEsExtContainerValueCodec) encodeChanged(value M1ThresholdEventA2ExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M3ConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[M3ConfigurationExtIEsExtContainer].
type M3ConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M3ConfigurationExtIEsExtContainer, error)
	encode  func(M3ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M3ConfigurationExtIEsExtContainer, aper.DecodeState) (M3ConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(M3ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M3ConfigurationExtIEsExtContainerValueCodec) New(value M3ConfigurationExtIEsExtContainer) (M3ConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return M3ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M3ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M3ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M3ConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M3ConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M3ConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M3ConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M3ConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M3ConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M3ConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M3ConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value M3ConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M3ConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value M3ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M3ConfigurationExtIEsExtContainerValueCodec) encodeChanged(value M3ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M4ConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[M4ConfigurationExtIEsExtContainer].
type M4ConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M4ConfigurationExtIEsExtContainer, error)
	encode  func(M4ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M4ConfigurationExtIEsExtContainer, aper.DecodeState) (M4ConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(M4ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M4ConfigurationExtIEsExtContainerValueCodec) New(value M4ConfigurationExtIEsExtContainer) (M4ConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return M4ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M4ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M4ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M4ConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M4ConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M4ConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M4ConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M4ConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M4ConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M4ConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M4ConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value M4ConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M4ConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value M4ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M4ConfigurationExtIEsExtContainerValueCodec) encodeChanged(value M4ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M5ConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[M5ConfigurationExtIEsExtContainer].
type M5ConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M5ConfigurationExtIEsExtContainer, error)
	encode  func(M5ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M5ConfigurationExtIEsExtContainer, aper.DecodeState) (M5ConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(M5ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M5ConfigurationExtIEsExtContainerValueCodec) New(value M5ConfigurationExtIEsExtContainer) (M5ConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return M5ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M5ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M5ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M5ConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M5ConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M5ConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M5ConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M5ConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M5ConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M5ConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M5ConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value M5ConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M5ConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value M5ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M5ConfigurationExtIEsExtContainerValueCodec) encodeChanged(value M5ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M6ConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[M6ConfigurationExtIEsExtContainer].
type M6ConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M6ConfigurationExtIEsExtContainer, error)
	encode  func(M6ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M6ConfigurationExtIEsExtContainer, aper.DecodeState) (M6ConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(M6ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M6ConfigurationExtIEsExtContainerValueCodec) New(value M6ConfigurationExtIEsExtContainer) (M6ConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return M6ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M6ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M6ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M6ConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M6ConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M6ConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M6ConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M6ConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M6ConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M6ConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M6ConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value M6ConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M6ConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value M6ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M6ConfigurationExtIEsExtContainerValueCodec) encodeChanged(value M6ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M7ConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[M7ConfigurationExtIEsExtContainer].
type M7ConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M7ConfigurationExtIEsExtContainer, error)
	encode  func(M7ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M7ConfigurationExtIEsExtContainer, aper.DecodeState) (M7ConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(M7ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M7ConfigurationExtIEsExtContainerValueCodec) New(value M7ConfigurationExtIEsExtContainer) (M7ConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return M7ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M7ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M7ConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M7ConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M7ConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M7ConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M7ConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M7ConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M7ConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M7ConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M7ConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value M7ConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M7ConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value M7ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M7ConfigurationExtIEsExtContainerValueCodec) encodeChanged(value M7ConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MBSFNResultToLogInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[MBSFNResultToLogInfoExtIEsExtContainer].
type MBSFNResultToLogInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtContainer, error)
	encode  func(MBSFNResultToLogInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MBSFNResultToLogInfoExtIEsExtContainer, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtContainer, aper.Snapshot)
	compare func(MBSFNResultToLogInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MBSFNResultToLogInfoExtIEsExtContainerValueCodec) New(value MBSFNResultToLogInfoExtIEsExtContainer) (MBSFNResultToLogInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MBSFNResultToLogInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MBSFNResultToLogInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MBSFNResultToLogInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MBSFNResultToLogInfoExtIEsExtContainerValueCodec) EncodeAPER(value MBSFNResultToLogInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MBSFNResultToLogInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value MBSFNResultToLogInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MBSFNResultToLogInfoExtIEsExtContainerValueCodec) encodeChanged(value MBSFNResultToLogInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessIEFieldValueCodec is the concrete ValueCodec[HandoverSuccessIEField].
type HandoverSuccessIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverSuccessIEField, error)
	encode  func(HandoverSuccessIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverSuccessIEField, aper.DecodeState) (HandoverSuccessIEField, aper.Snapshot)
	compare func(HandoverSuccessIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverSuccessIEFieldValueCodec) New(value HandoverSuccessIEField) (HandoverSuccessIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverSuccessIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverSuccessIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverSuccessIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverSuccessIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverSuccessIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverSuccessIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverSuccessIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverSuccessIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverSuccessIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverSuccessIEFieldValueCodec) EncodeAPER(value HandoverSuccessIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverSuccessIEFieldValueCodec) encodeBudgetValue(value HandoverSuccessIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverSuccessIEFieldValueCodec) encodeChanged(value HandoverSuccessIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessIEContainerValueCodec is the concrete ValueCodec[HandoverSuccessIEContainer].
type HandoverSuccessIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverSuccessIEContainer, error)
	encode  func(HandoverSuccessIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverSuccessIEContainer, aper.DecodeState) (HandoverSuccessIEContainer, aper.Snapshot)
	compare func(HandoverSuccessIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverSuccessIEContainerValueCodec) New(value HandoverSuccessIEContainer) (HandoverSuccessIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverSuccessIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverSuccessIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverSuccessIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverSuccessIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverSuccessIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverSuccessIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverSuccessIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverSuccessIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverSuccessIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverSuccessIEContainerValueCodec) EncodeAPER(value HandoverSuccessIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverSuccessIEContainerValueCodec) encodeBudgetValue(value HandoverSuccessIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverSuccessIEContainerValueCodec) encodeChanged(value HandoverSuccessIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[HandoverSuccessIEValueProtocolErrorIEContainerList].
type HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverSuccessIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverSuccessIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverSuccessIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverSuccessIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverSuccessIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverSuccessIEValueProtocolErrorIEContainerList) (HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverSuccessIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverSuccessIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{HandoverSuccessIEs}} of TS 36.413: a list of information element fields.
type HandoverSuccessIEValueProtocolErrorIEContainerList []HandoverSuccessIEValueProtocolIESingleContainer

// HandoverSuccessIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[HandoverSuccessIEValueProtocolIEContainerList].
type HandoverSuccessIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverSuccessIEValueProtocolIEContainerList, error)
	encode  func(HandoverSuccessIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverSuccessIEValueProtocolIEContainerList, aper.DecodeState) (HandoverSuccessIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverSuccessIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverSuccessIEValueProtocolIEContainerListValueCodec) New(value HandoverSuccessIEValueProtocolIEContainerList) (HandoverSuccessIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverSuccessIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverSuccessIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverSuccessIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverSuccessIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverSuccessIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverSuccessIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverSuccessIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverSuccessIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverSuccessIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverSuccessIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverSuccessIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverSuccessIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverSuccessIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverSuccessIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverSuccessIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {HandoverSuccessIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type HandoverSuccessIEValueProtocolIEContainerList []HandoverSuccessIEValueProtocolIESingleContainer

// HandoverSuccessIEValueERABIEContainerListAPERValue is the concrete APERValue[HandoverSuccessIEValueERABIEContainerList].
type HandoverSuccessIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverSuccessIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverSuccessIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverSuccessIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverSuccessIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverSuccessIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{HandoverSuccessIEs}} of TS 36.413: a single information element field.
type HandoverSuccessIEValueProtocolIESingleContainer = HandoverSuccessIEField

// GBRQosInformationExtIEsExtFieldAPERValue is the concrete APERValue[GBRQosInformationExtIEsExtField].
type GBRQosInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GBRQosInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GBRQosInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GBRQosInformationExtIEsExtFieldAPERValue) WithoutReplay() GBRQosInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GERANCellIDExtIEsExtFieldAPERValue is the concrete APERValue[GERANCellIDExtIEsExtField].
type GERANCellIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GERANCellIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GERANCellIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GERANCellIDExtIEsExtFieldAPERValue) WithoutReplay() GERANCellIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GNBExtIEsExtFieldAPERValue is the concrete APERValue[GNBExtIEsExtField].
type GNBExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GNBExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GNBExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GNBExtIEsExtFieldAPERValue) WithoutReplay() GNBExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GUMMEIExtIEsExtFieldAPERValue is the concrete APERValue[GUMMEIExtIEsExtField].
type GUMMEIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GUMMEIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GUMMEIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GUMMEIExtIEsExtFieldAPERValue) WithoutReplay() GUMMEIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalENBIDExtIEsExtFieldAPERValue is the concrete APERValue[GlobalENBIDExtIEsExtField].
type GlobalENBIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GlobalENBIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalENBIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalENBIDExtIEsExtFieldAPERValue) WithoutReplay() GlobalENBIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalEnGNBIDExtIEsExtFieldAPERValue is the concrete APERValue[GlobalEnGNBIDExtIEsExtField].
type GlobalEnGNBIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GlobalEnGNBIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalEnGNBIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalEnGNBIDExtIEsExtFieldAPERValue) WithoutReplay() GlobalEnGNBIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalGNBIDExtIEsExtFieldAPERValue is the concrete APERValue[GlobalGNBIDExtIEsExtField].
type GlobalGNBIDExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GlobalGNBIDExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalGNBIDExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalGNBIDExtIEsExtFieldAPERValue) WithoutReplay() GlobalGNBIDExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InformationForCECapableUEsExtIEsExtFieldAPERValue is the concrete APERValue[InformationForCECapableUEsExtIEsExtField].
type InformationForCECapableUEsExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InformationForCECapableUEsExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InformationForCECapableUEsExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationForCECapableUEsExtIEsExtFieldAPERValue) WithoutReplay() InformationForCECapableUEsExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue is the concrete APERValue[InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField].
type InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue) WithoutReplay() InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementItemExtIEsExtFieldAPERValue is the concrete APERValue[InterSystemMeasurementItemExtIEsExtField].
type InterSystemMeasurementItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InterSystemMeasurementItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementItemExtIEsExtFieldAPERValue) WithoutReplay() InterSystemMeasurementItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementParametersExtIEsExtFieldAPERValue is the concrete APERValue[InterSystemMeasurementParametersExtIEsExtField].
type InterSystemMeasurementParametersExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InterSystemMeasurementParametersExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementParametersExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementParametersExtIEsExtFieldAPERValue) WithoutReplay() InterSystemMeasurementParametersExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[IntersystemMeasurementConfigurationExtIEsExtField].
type IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         IntersystemMeasurementConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue) WithoutReplay() IntersystemMeasurementConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LAIExtIEsExtFieldAPERValue is the concrete APERValue[LAIExtIEsExtField].
type LAIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LAIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LAIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LAIExtIEsExtFieldAPERValue) WithoutReplay() LAIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LTENTNTAIInformationExtIEsExtFieldAPERValue is the concrete APERValue[LTENTNTAIInformationExtIEsExtField].
type LTENTNTAIInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LTENTNTAIInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LTENTNTAIInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LTENTNTAIInformationExtIEsExtFieldAPERValue) WithoutReplay() LTENTNTAIInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedPSCellInformationExtIEsExtFieldAPERValue is the concrete APERValue[LastVisitedPSCellInformationExtIEsExtField].
type LastVisitedPSCellInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LastVisitedPSCellInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedPSCellInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedPSCellInformationExtIEsExtFieldAPERValue) WithoutReplay() LastVisitedPSCellInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ListeningSubframePatternExtIEsExtFieldAPERValue is the concrete APERValue[ListeningSubframePatternExtIEsExtField].
type ListeningSubframePatternExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ListeningSubframePatternExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ListeningSubframePatternExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ListeningSubframePatternExtIEsExtFieldAPERValue) WithoutReplay() ListeningSubframePatternExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggedMBSFNMDTExtIEsExtFieldAPERValue is the concrete APERValue[LoggedMBSFNMDTExtIEsExtField].
type LoggedMBSFNMDTExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LoggedMBSFNMDTExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMBSFNMDTExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMBSFNMDTExtIEsExtFieldAPERValue) WithoutReplay() LoggedMBSFNMDTExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M1PeriodicReportingExtIEsExtFieldAPERValue is the concrete APERValue[M1PeriodicReportingExtIEsExtField].
type M1PeriodicReportingExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M1PeriodicReportingExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M1PeriodicReportingExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1PeriodicReportingExtIEsExtFieldAPERValue) WithoutReplay() M1PeriodicReportingExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M1ThresholdEventA2ExtIEsExtFieldAPERValue is the concrete APERValue[M1ThresholdEventA2ExtIEsExtField].
type M1ThresholdEventA2ExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M1ThresholdEventA2ExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M1ThresholdEventA2ExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1ThresholdEventA2ExtIEsExtFieldAPERValue) WithoutReplay() M1ThresholdEventA2ExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M3ConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[M3ConfigurationExtIEsExtField].
type M3ConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M3ConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M3ConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M3ConfigurationExtIEsExtFieldAPERValue) WithoutReplay() M3ConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M4ConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[M4ConfigurationExtIEsExtField].
type M4ConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M4ConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M4ConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M4ConfigurationExtIEsExtFieldAPERValue) WithoutReplay() M4ConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M5ConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[M5ConfigurationExtIEsExtField].
type M5ConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M5ConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M5ConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M5ConfigurationExtIEsExtFieldAPERValue) WithoutReplay() M5ConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M6ConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[M6ConfigurationExtIEsExtField].
type M6ConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M6ConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M6ConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6ConfigurationExtIEsExtFieldAPERValue) WithoutReplay() M6ConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M7ConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[M7ConfigurationExtIEsExtField].
type M7ConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M7ConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M7ConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M7ConfigurationExtIEsExtFieldAPERValue) WithoutReplay() M7ConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNResultToLogInfoExtIEsExtFieldAPERValue is the concrete APERValue[MBSFNResultToLogInfoExtIEsExtField].
type MBSFNResultToLogInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MBSFNResultToLogInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MBSFNResultToLogInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MBSFNResultToLogInfoExtIEsExtFieldAPERValue) WithoutReplay() MBSFNResultToLogInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GBRQosInformationExtIEsExtContainerAPERValue is the concrete APERValue[GBRQosInformationExtIEsExtContainer].
type GBRQosInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GBRQosInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GBRQosInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GBRQosInformationExtIEsExtContainerAPERValue) WithoutReplay() GBRQosInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GERANCellIDExtIEsExtContainerAPERValue is the concrete APERValue[GERANCellIDExtIEsExtContainer].
type GERANCellIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GERANCellIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GERANCellIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GERANCellIDExtIEsExtContainerAPERValue) WithoutReplay() GERANCellIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GNBExtIEsExtContainerAPERValue is the concrete APERValue[GNBExtIEsExtContainer].
type GNBExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GNBExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GNBExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GNBExtIEsExtContainerAPERValue) WithoutReplay() GNBExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GUMMEIExtIEsExtContainerAPERValue is the concrete APERValue[GUMMEIExtIEsExtContainer].
type GUMMEIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GUMMEIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GUMMEIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GUMMEIExtIEsExtContainerAPERValue) WithoutReplay() GUMMEIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalENBIDExtIEsExtContainerAPERValue is the concrete APERValue[GlobalENBIDExtIEsExtContainer].
type GlobalENBIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GlobalENBIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalENBIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalENBIDExtIEsExtContainerAPERValue) WithoutReplay() GlobalENBIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalEnGNBIDExtIEsExtContainerAPERValue is the concrete APERValue[GlobalEnGNBIDExtIEsExtContainer].
type GlobalEnGNBIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GlobalEnGNBIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalEnGNBIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalEnGNBIDExtIEsExtContainerAPERValue) WithoutReplay() GlobalEnGNBIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalGNBIDExtIEsExtContainerAPERValue is the concrete APERValue[GlobalGNBIDExtIEsExtContainer].
type GlobalGNBIDExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         GlobalGNBIDExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalGNBIDExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalGNBIDExtIEsExtContainerAPERValue) WithoutReplay() GlobalGNBIDExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InformationForCECapableUEsExtIEsExtContainerAPERValue is the concrete APERValue[InformationForCECapableUEsExtIEsExtContainer].
type InformationForCECapableUEsExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InformationForCECapableUEsExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InformationForCECapableUEsExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationForCECapableUEsExtIEsExtContainerAPERValue) WithoutReplay() InformationForCECapableUEsExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue is the concrete APERValue[InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer].
type InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue) WithoutReplay() InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementItemExtIEsExtContainerAPERValue is the concrete APERValue[InterSystemMeasurementItemExtIEsExtContainer].
type InterSystemMeasurementItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InterSystemMeasurementItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementItemExtIEsExtContainerAPERValue) WithoutReplay() InterSystemMeasurementItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementParametersExtIEsExtContainerAPERValue is the concrete APERValue[InterSystemMeasurementParametersExtIEsExtContainer].
type InterSystemMeasurementParametersExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InterSystemMeasurementParametersExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementParametersExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementParametersExtIEsExtContainerAPERValue) WithoutReplay() InterSystemMeasurementParametersExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[IntersystemMeasurementConfigurationExtIEsExtContainer].
type IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         IntersystemMeasurementConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue) WithoutReplay() IntersystemMeasurementConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LAIExtIEsExtContainerAPERValue is the concrete APERValue[LAIExtIEsExtContainer].
type LAIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LAIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LAIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LAIExtIEsExtContainerAPERValue) WithoutReplay() LAIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LTENTNTAIInformationExtIEsExtContainerAPERValue is the concrete APERValue[LTENTNTAIInformationExtIEsExtContainer].
type LTENTNTAIInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LTENTNTAIInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LTENTNTAIInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LTENTNTAIInformationExtIEsExtContainerAPERValue) WithoutReplay() LTENTNTAIInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedPSCellInformationExtIEsExtContainerAPERValue is the concrete APERValue[LastVisitedPSCellInformationExtIEsExtContainer].
type LastVisitedPSCellInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LastVisitedPSCellInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedPSCellInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedPSCellInformationExtIEsExtContainerAPERValue) WithoutReplay() LastVisitedPSCellInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ListeningSubframePatternExtIEsExtContainerAPERValue is the concrete APERValue[ListeningSubframePatternExtIEsExtContainer].
type ListeningSubframePatternExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ListeningSubframePatternExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ListeningSubframePatternExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ListeningSubframePatternExtIEsExtContainerAPERValue) WithoutReplay() ListeningSubframePatternExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggedMBSFNMDTExtIEsExtContainerAPERValue is the concrete APERValue[LoggedMBSFNMDTExtIEsExtContainer].
type LoggedMBSFNMDTExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LoggedMBSFNMDTExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMBSFNMDTExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMBSFNMDTExtIEsExtContainerAPERValue) WithoutReplay() LoggedMBSFNMDTExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M1PeriodicReportingExtIEsExtContainerAPERValue is the concrete APERValue[M1PeriodicReportingExtIEsExtContainer].
type M1PeriodicReportingExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M1PeriodicReportingExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M1PeriodicReportingExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1PeriodicReportingExtIEsExtContainerAPERValue) WithoutReplay() M1PeriodicReportingExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M1ThresholdEventA2ExtIEsExtContainerAPERValue is the concrete APERValue[M1ThresholdEventA2ExtIEsExtContainer].
type M1ThresholdEventA2ExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M1ThresholdEventA2ExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M1ThresholdEventA2ExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1ThresholdEventA2ExtIEsExtContainerAPERValue) WithoutReplay() M1ThresholdEventA2ExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M3ConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[M3ConfigurationExtIEsExtContainer].
type M3ConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M3ConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M3ConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M3ConfigurationExtIEsExtContainerAPERValue) WithoutReplay() M3ConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M4ConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[M4ConfigurationExtIEsExtContainer].
type M4ConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M4ConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M4ConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M4ConfigurationExtIEsExtContainerAPERValue) WithoutReplay() M4ConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M5ConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[M5ConfigurationExtIEsExtContainer].
type M5ConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M5ConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M5ConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M5ConfigurationExtIEsExtContainerAPERValue) WithoutReplay() M5ConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M6ConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[M6ConfigurationExtIEsExtContainer].
type M6ConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M6ConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M6ConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6ConfigurationExtIEsExtContainerAPERValue) WithoutReplay() M6ConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M7ConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[M7ConfigurationExtIEsExtContainer].
type M7ConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         M7ConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M7ConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M7ConfigurationExtIEsExtContainerAPERValue) WithoutReplay() M7ConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNResultToLogInfoExtIEsExtContainerAPERValue is the concrete APERValue[MBSFNResultToLogInfoExtIEsExtContainer].
type MBSFNResultToLogInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MBSFNResultToLogInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MBSFNResultToLogInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MBSFNResultToLogInfoExtIEsExtContainerAPERValue) WithoutReplay() MBSFNResultToLogInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverSuccessIEFieldAPERValue is the concrete APERValue[HandoverSuccessIEField].
type HandoverSuccessIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverSuccessIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverSuccessIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverSuccessIEFieldAPERValue) WithoutReplay() HandoverSuccessIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverSuccessIEContainerAPERValue is the concrete APERValue[HandoverSuccessIEContainer].
type HandoverSuccessIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverSuccessIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverSuccessIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverSuccessIEContainerAPERValue) WithoutReplay() HandoverSuccessIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[HandoverSuccessIEValueProtocolErrorIEContainerList].
type HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverSuccessIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverSuccessIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverSuccessIEValueProtocolIEContainerListAPERValue is the concrete APERValue[HandoverSuccessIEValueProtocolIEContainerList].
type HandoverSuccessIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverSuccessIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverSuccessIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverSuccessIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverSuccessIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APHandoverSuccessIEValue(v *HandoverSuccessIEValue, s *aper.SemanticCapture) {
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverSuccessIEValue) captureSemantics(s aper.SemanticCapture) HandoverSuccessIEValue {
	BridgeCaptureS1APHandoverSuccessIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverSuccessIEValue(v *HandoverSuccessIEValue, s *aper.SemanticComparison) {
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverSuccessIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverSuccessIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMECPRelocationIndicationIEValue(v *MMECPRelocationIndicationIEValue, s *aper.SemanticCapture) {
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMECPRelocationIndicationIEValue) captureSemantics(s aper.SemanticCapture) MMECPRelocationIndicationIEValue {
	BridgeCaptureS1APMMECPRelocationIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMECPRelocationIndicationIEValue(v *MMECPRelocationIndicationIEValue, s *aper.SemanticComparison) {
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMECPRelocationIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMECPRelocationIndicationIEValue(&v, &s)
	return s
}

type HandoverSuccessIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
}

func (v HandoverSuccessIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	}
	return false
}

// Opaque returns the retained opaque open value of HandoverSuccessIEValue and reports whether the opaque alternative is selected.
func (v *HandoverSuccessIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverSuccessIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverSuccessIEs"}}
}
func (HandoverSuccessIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverSuccessIEValue and reports whether that alternative is active.
func (v *HandoverSuccessIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverSuccessIEValue and reports whether that alternative is active.
func (v *HandoverSuccessIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v HandoverSuccessIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverSuccessIEValue, error) {
	out := HandoverSuccessIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
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
func (v HandoverSuccessIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverSuccessIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverSuccessIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverSuccessIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverSuccessIEValue:", v.id)
	}
}

type MMECPRelocationIndicationIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
}

func (v MMECPRelocationIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	}
	return false
}

// Opaque returns the retained opaque open value of MMECPRelocationIndicationIEValue and reports whether the opaque alternative is selected.
func (v *MMECPRelocationIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMECPRelocationIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMECPRelocationIndicationIEs"}}
}
func (MMECPRelocationIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of MMECPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *MMECPRelocationIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of MMECPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *MMECPRelocationIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v MMECPRelocationIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMECPRelocationIndicationIEValue, error) {
	out := MMECPRelocationIndicationIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
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
func (v MMECPRelocationIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MMECPRelocationIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "MMECPRelocationIndicationIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "MMECPRelocationIndicationIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMECPRelocationIndicationIEValue:", v.id)
	}
}

type GBRQosInformationExtIETable struct{}

func GBRQosInformationExtIEs() GBRQosInformationExtIETable { return GBRQosInformationExtIETable{} }

// ID returns the ASN.1 object-set identity of GBRQosInformationExtIETable.
func (GBRQosInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GBR-QosInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by GBRQosInformationExtIETable.
func (GBRQosInformationExtIETable) Table() s00.GBRQosInformationExtIEsValueExtensionTable {
	return func() s00.GBRQosInformationExtIEsValueExtensionTable {
		sealed := s00.GBRQosInformationExtIEsValueExtensionTable{}
		*s00.BridgeGBRQosInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (GBRQosInformationExtIETable) infoExtendedERABMaximumBitrateDL() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: GBRQosInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(255), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExtendedBitRate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GBR-QosInformation-ExtIEs", Row: "id-extended-e-RAB-MaximumBitrateDL"}}}
}

// ExtendedERABMaximumBitrateDL returns the typed binding for the ExtendedERABMaximumBitrateDL row of GBRQosInformationExtIETable.
func (t GBRQosInformationExtIETable) ExtendedERABMaximumBitrateDL() GBRQosInformationExtIEsExtendedBitRateExtBinding {
	return GBRQosInformationExtIEsExtendedBitRateExtBinding{info: t.infoExtendedERABMaximumBitrateDL(), codec: func() s00.ExtendedBitRateValueCodec {
		sealed := s00.ExtendedBitRateValueCodec{}
		*s00.BridgeExtendedBitRateValueCodecFieldPath(&sealed) = "ExtendedBitRate"
		*s00.BridgeExtendedBitRateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedBitRate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ExtendedBitRate")
			var zero s05.GBRQosInformationExtIEsValue
			decoded, err := s05.BridgeGBRQosInformationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(255), raw)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, runtime.WrapDecodePath(err, "ExtendedBitRate")
			}
			value, ok := decoded.AsExtendedERABMaximumBitrateDL()
			if !ok {
				var empty s00.ExtendedBitRate
				return empty, fmt.Errorf("binding GBR-QosInformation-ExtIEs.id-extended-e-RAB-MaximumBitrateDL: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeExtendedBitRateValueCodecFieldEncode(&sealed) = func(value s00.ExtendedBitRate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeGBRQosInformationExtIEsValueMethodEncodeFresh((func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(255)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateDL(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCapture(&sealed) = func(v s00.ExtendedBitRate, options aper.DecodeState) (s00.ExtendedBitRate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedBitRate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCompare(&sealed) = func(v s00.ExtendedBitRate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APExtendedBitRate(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeExtendedBitRateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedBitRate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ExtendedBitRate) s05.GBRQosInformationExtIEsValue {
			return func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(255)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateDL(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.GBRQosInformationExtIEsValue) (*s00.ExtendedBitRate, bool) {
			return value.AsExtendedERABMaximumBitrateDL()
		}}
}
func (GBRQosInformationExtIETable) infoExtendedERABMaximumBitrateUL() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: GBRQosInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(256), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExtendedBitRate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GBR-QosInformation-ExtIEs", Row: "id-extended-e-RAB-MaximumBitrateUL"}}}
}

// ExtendedERABMaximumBitrateUL returns the typed binding for the ExtendedERABMaximumBitrateUL row of GBRQosInformationExtIETable.
func (t GBRQosInformationExtIETable) ExtendedERABMaximumBitrateUL() GBRQosInformationExtIEsExtendedBitRateExtBinding {
	return GBRQosInformationExtIEsExtendedBitRateExtBinding{info: t.infoExtendedERABMaximumBitrateUL(), codec: func() s00.ExtendedBitRateValueCodec {
		sealed := s00.ExtendedBitRateValueCodec{}
		*s00.BridgeExtendedBitRateValueCodecFieldPath(&sealed) = "ExtendedBitRate"
		*s00.BridgeExtendedBitRateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedBitRate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ExtendedBitRate")
			var zero s05.GBRQosInformationExtIEsValue
			decoded, err := s05.BridgeGBRQosInformationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(256), raw)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, runtime.WrapDecodePath(err, "ExtendedBitRate")
			}
			value, ok := decoded.AsExtendedERABMaximumBitrateUL()
			if !ok {
				var empty s00.ExtendedBitRate
				return empty, fmt.Errorf("binding GBR-QosInformation-ExtIEs.id-extended-e-RAB-MaximumBitrateUL: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeExtendedBitRateValueCodecFieldEncode(&sealed) = func(value s00.ExtendedBitRate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeGBRQosInformationExtIEsValueMethodEncodeFresh((func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(256)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateUL(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCapture(&sealed) = func(v s00.ExtendedBitRate, options aper.DecodeState) (s00.ExtendedBitRate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedBitRate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCompare(&sealed) = func(v s00.ExtendedBitRate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APExtendedBitRate(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeExtendedBitRateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedBitRate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ExtendedBitRate) s05.GBRQosInformationExtIEsValue {
			return func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(256)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateUL(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.GBRQosInformationExtIEsValue) (*s00.ExtendedBitRate, bool) {
			return value.AsExtendedERABMaximumBitrateUL()
		}}
}
func (GBRQosInformationExtIETable) infoExtendedERABGuaranteedBitrateDL() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: GBRQosInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(257), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExtendedBitRate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GBR-QosInformation-ExtIEs", Row: "id-extended-e-RAB-GuaranteedBitrateDL"}}}
}

// ExtendedERABGuaranteedBitrateDL returns the typed binding for the ExtendedERABGuaranteedBitrateDL row of GBRQosInformationExtIETable.
func (t GBRQosInformationExtIETable) ExtendedERABGuaranteedBitrateDL() GBRQosInformationExtIEsExtendedBitRateExtBinding {
	return GBRQosInformationExtIEsExtendedBitRateExtBinding{info: t.infoExtendedERABGuaranteedBitrateDL(), codec: func() s00.ExtendedBitRateValueCodec {
		sealed := s00.ExtendedBitRateValueCodec{}
		*s00.BridgeExtendedBitRateValueCodecFieldPath(&sealed) = "ExtendedBitRate"
		*s00.BridgeExtendedBitRateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedBitRate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ExtendedBitRate")
			var zero s05.GBRQosInformationExtIEsValue
			decoded, err := s05.BridgeGBRQosInformationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(257), raw)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, runtime.WrapDecodePath(err, "ExtendedBitRate")
			}
			value, ok := decoded.AsExtendedERABGuaranteedBitrateDL()
			if !ok {
				var empty s00.ExtendedBitRate
				return empty, fmt.Errorf("binding GBR-QosInformation-ExtIEs.id-extended-e-RAB-GuaranteedBitrateDL: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeExtendedBitRateValueCodecFieldEncode(&sealed) = func(value s00.ExtendedBitRate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeGBRQosInformationExtIEsValueMethodEncodeFresh((func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(257)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateDL(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCapture(&sealed) = func(v s00.ExtendedBitRate, options aper.DecodeState) (s00.ExtendedBitRate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedBitRate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCompare(&sealed) = func(v s00.ExtendedBitRate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APExtendedBitRate(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeExtendedBitRateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedBitRate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ExtendedBitRate) s05.GBRQosInformationExtIEsValue {
			return func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(257)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateDL(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.GBRQosInformationExtIEsValue) (*s00.ExtendedBitRate, bool) {
			return value.AsExtendedERABGuaranteedBitrateDL()
		}}
}
func (GBRQosInformationExtIETable) infoExtendedERABGuaranteedBitrateUL() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: GBRQosInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(258), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExtendedBitRate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GBR-QosInformation-ExtIEs", Row: "id-extended-e-RAB-GuaranteedBitrateUL"}}}
}

// ExtendedERABGuaranteedBitrateUL returns the typed binding for the ExtendedERABGuaranteedBitrateUL row of GBRQosInformationExtIETable.
func (t GBRQosInformationExtIETable) ExtendedERABGuaranteedBitrateUL() GBRQosInformationExtIEsExtendedBitRateExtBinding {
	return GBRQosInformationExtIEsExtendedBitRateExtBinding{info: t.infoExtendedERABGuaranteedBitrateUL(), codec: func() s00.ExtendedBitRateValueCodec {
		sealed := s00.ExtendedBitRateValueCodec{}
		*s00.BridgeExtendedBitRateValueCodecFieldPath(&sealed) = "ExtendedBitRate"
		*s00.BridgeExtendedBitRateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedBitRate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ExtendedBitRate")
			var zero s05.GBRQosInformationExtIEsValue
			decoded, err := s05.BridgeGBRQosInformationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(258), raw)
			if err != nil {
				var empty s00.ExtendedBitRate
				return empty, runtime.WrapDecodePath(err, "ExtendedBitRate")
			}
			value, ok := decoded.AsExtendedERABGuaranteedBitrateUL()
			if !ok {
				var empty s00.ExtendedBitRate
				return empty, fmt.Errorf("binding GBR-QosInformation-ExtIEs.id-extended-e-RAB-GuaranteedBitrateUL: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeExtendedBitRateValueCodecFieldEncode(&sealed) = func(value s00.ExtendedBitRate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeGBRQosInformationExtIEsValueMethodEncodeFresh((func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(258)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateUL(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCapture(&sealed) = func(v s00.ExtendedBitRate, options aper.DecodeState) (s00.ExtendedBitRate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedBitRate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeExtendedBitRateValueCodecFieldCompare(&sealed) = func(v s00.ExtendedBitRate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APExtendedBitRate(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeExtendedBitRateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedBitRate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ExtendedBitRate) s05.GBRQosInformationExtIEsValue {
			return func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(258)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateUL(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.GBRQosInformationExtIEsValue) (*s00.ExtendedBitRate, bool) {
			return value.AsExtendedERABGuaranteedBitrateUL()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in GBRQosInformationExtIETable.
func (t GBRQosInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (GBRQosInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(255):
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-extended-e-RAB-MaximumBitrateDL requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(256):
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-extended-e-RAB-MaximumBitrateUL requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(257):
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-extended-e-RAB-GuaranteedBitrateDL requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(258):
		return GBRQosInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-extended-e-RAB-GuaranteedBitrateUL requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return GBRQosInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return GBRQosInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return GBRQosInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.GBRQosInformationExtIEsValue {
			sealed := s05.GBRQosInformationExtIEsValue{}
			*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeGBRQosInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeGBRQosInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type GERANCellIDExtIETable struct{}

func GERANCellIDExtIEs() GERANCellIDExtIETable { return GERANCellIDExtIETable{} }

// ID returns the ASN.1 object-set identity of GERANCellIDExtIETable.
func (GERANCellIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GERAN-Cell-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by GERANCellIDExtIETable.
func (GERANCellIDExtIETable) Table() s00.GERANCellIDExtIEsValueExtensionTable {
	return func() s00.GERANCellIDExtIEsValueExtensionTable {
		sealed := s00.GERANCellIDExtIEsValueExtensionTable{}
		*s00.BridgeGERANCellIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in GERANCellIDExtIETable.
func (t GERANCellIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (GERANCellIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return GERANCellIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return GERANCellIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return GERANCellIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return GERANCellIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.GERANCellIDExtIEsValue {
			sealed := s05.GERANCellIDExtIEsValue{}
			*s05.BridgeGERANCellIDExtIEsValueFieldId(&sealed) = id
			*s05.BridgeGERANCellIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeGERANCellIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type GNBExtIETable struct{}

func GNBExtIEs() GNBExtIETable { return GNBExtIETable{} }

// ID returns the ASN.1 object-set identity of GNBExtIETable.
func (GNBExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GNB-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by GNBExtIETable.
func (GNBExtIETable) Table() s00.GNBExtIEsValueExtensionTable {
	return func() s00.GNBExtIEsValueExtensionTable {
		sealed := s00.GNBExtIEsValueExtensionTable{}
		*s00.BridgeGNBExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in GNBExtIETable.
func (t GNBExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (GNBExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return GNBExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return GNBExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return GNBExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return GNBExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.GNBExtIEsValue {
			sealed := s05.GNBExtIEsValue{}
			*s05.BridgeGNBExtIEsValueFieldId(&sealed) = id
			*s05.BridgeGNBExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeGNBExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type GUMMEIExtIETable struct{}

func GUMMEIExtIEs() GUMMEIExtIETable { return GUMMEIExtIETable{} }

// ID returns the ASN.1 object-set identity of GUMMEIExtIETable.
func (GUMMEIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by GUMMEIExtIETable.
func (GUMMEIExtIETable) Table() s00.GUMMEIExtIEsValueExtensionTable {
	return func() s00.GUMMEIExtIEsValueExtensionTable {
		sealed := s00.GUMMEIExtIEsValueExtensionTable{}
		*s00.BridgeGUMMEIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in GUMMEIExtIETable.
func (t GUMMEIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (GUMMEIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return GUMMEIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return GUMMEIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return GUMMEIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return GUMMEIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.GUMMEIExtIEsValue {
			sealed := s05.GUMMEIExtIEsValue{}
			*s05.BridgeGUMMEIExtIEsValueFieldId(&sealed) = id
			*s05.BridgeGUMMEIExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeGUMMEIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type GlobalGNBIDExtIETable struct{}

func GlobalGNBIDExtIEs() GlobalGNBIDExtIETable { return GlobalGNBIDExtIETable{} }

// ID returns the ASN.1 object-set identity of GlobalGNBIDExtIETable.
func (GlobalGNBIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-GNB-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by GlobalGNBIDExtIETable.
func (GlobalGNBIDExtIETable) Table() s00.GlobalGNBIDExtIEsValueExtensionTable {
	return func() s00.GlobalGNBIDExtIEsValueExtensionTable {
		sealed := s00.GlobalGNBIDExtIEsValueExtensionTable{}
		*s00.BridgeGlobalGNBIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in GlobalGNBIDExtIETable.
func (t GlobalGNBIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (GlobalGNBIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return GlobalGNBIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return GlobalGNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return GlobalGNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return GlobalGNBIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.GlobalGNBIDExtIEsValue {
			sealed := s05.GlobalGNBIDExtIEsValue{}
			*s05.BridgeGlobalGNBIDExtIEsValueFieldId(&sealed) = id
			*s05.BridgeGlobalGNBIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeGlobalGNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type GlobalEnGNBIDExtIETable struct{}

func GlobalEnGNBIDExtIEs() GlobalEnGNBIDExtIETable { return GlobalEnGNBIDExtIETable{} }

// ID returns the ASN.1 object-set identity of GlobalEnGNBIDExtIETable.
func (GlobalEnGNBIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-en-gNB-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by GlobalEnGNBIDExtIETable.
func (GlobalEnGNBIDExtIETable) Table() s00.GlobalEnGNBIDExtIEsValueExtensionTable {
	return func() s00.GlobalEnGNBIDExtIEsValueExtensionTable {
		sealed := s00.GlobalEnGNBIDExtIEsValueExtensionTable{}
		*s00.BridgeGlobalEnGNBIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in GlobalEnGNBIDExtIETable.
func (t GlobalEnGNBIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (GlobalEnGNBIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return GlobalEnGNBIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return GlobalEnGNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return GlobalEnGNBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return GlobalEnGNBIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.GlobalEnGNBIDExtIEsValue {
			sealed := s05.GlobalEnGNBIDExtIEsValue{}
			*s05.BridgeGlobalEnGNBIDExtIEsValueFieldId(&sealed) = id
			*s05.BridgeGlobalEnGNBIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeGlobalEnGNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type GlobalENBIDExtIETable struct{}

func GlobalENBIDExtIEs() GlobalENBIDExtIETable { return GlobalENBIDExtIETable{} }

// ID returns the ASN.1 object-set identity of GlobalENBIDExtIETable.
func (GlobalENBIDExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GlobalENB-ID-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by GlobalENBIDExtIETable.
func (GlobalENBIDExtIETable) Table() s00.GlobalENBIDExtIEsValueExtensionTable {
	return func() s00.GlobalENBIDExtIEsValueExtensionTable {
		sealed := s00.GlobalENBIDExtIEsValueExtensionTable{}
		*s00.BridgeGlobalENBIDExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in GlobalENBIDExtIETable.
func (t GlobalENBIDExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (GlobalENBIDExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return GlobalENBIDExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return GlobalENBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return GlobalENBIDExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return GlobalENBIDExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.GlobalENBIDExtIEsValue {
			sealed := s05.GlobalENBIDExtIEsValue{}
			*s05.BridgeGlobalENBIDExtIEsValueFieldId(&sealed) = id
			*s05.BridgeGlobalENBIDExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeGlobalENBIDExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type InformationForCECapableUEsExtIETable struct{}

func InformationForCECapableUEsExtIEs() InformationForCECapableUEsExtIETable {
	return InformationForCECapableUEsExtIETable{}
}

// ID returns the ASN.1 object-set identity of InformationForCECapableUEsExtIETable.
func (InformationForCECapableUEsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "InformationForCECapableUEs-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by InformationForCECapableUEsExtIETable.
func (InformationForCECapableUEsExtIETable) Table() s00.InformationForCECapableUEsExtIEsValueExtensionTable {
	return func() s00.InformationForCECapableUEsExtIEsValueExtensionTable {
		sealed := s00.InformationForCECapableUEsExtIEsValueExtensionTable{}
		*s00.BridgeInformationForCECapableUEsExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in InformationForCECapableUEsExtIETable.
func (t InformationForCECapableUEsExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (InformationForCECapableUEsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InformationForCECapableUEsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InformationForCECapableUEsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InformationForCECapableUEsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return InformationForCECapableUEsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.InformationForCECapableUEsExtIEsValue {
			sealed := s05.InformationForCECapableUEsExtIEsValue{}
			*s05.BridgeInformationForCECapableUEsExtIEsValueFieldId(&sealed) = id
			*s05.BridgeInformationForCECapableUEsExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeInformationForCECapableUEsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type InformationOnRecommendedCellsAndENBsForPagingExtIETable struct{}

func InformationOnRecommendedCellsAndENBsForPagingExtIEs() InformationOnRecommendedCellsAndENBsForPagingExtIETable {
	return InformationOnRecommendedCellsAndENBsForPagingExtIETable{}
}

// ID returns the ASN.1 object-set identity of InformationOnRecommendedCellsAndENBsForPagingExtIETable.
func (InformationOnRecommendedCellsAndENBsForPagingExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "InformationOnRecommendedCellsAndENBsForPaging-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by InformationOnRecommendedCellsAndENBsForPagingExtIETable.
func (InformationOnRecommendedCellsAndENBsForPagingExtIETable) Table() s00.InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTable {
	return func() s00.InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTable {
		sealed := s00.InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTable{}
		*s00.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in InformationOnRecommendedCellsAndENBsForPagingExtIETable.
func (t InformationOnRecommendedCellsAndENBsForPagingExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue {
			sealed := s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue{}
			*s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueFieldId(&sealed) = id
			*s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type InterSystemMeasurementItemExtIETable struct{}

func InterSystemMeasurementItemExtIEs() InterSystemMeasurementItemExtIETable {
	return InterSystemMeasurementItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of InterSystemMeasurementItemExtIETable.
func (InterSystemMeasurementItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "InterSystemMeasurementItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by InterSystemMeasurementItemExtIETable.
func (InterSystemMeasurementItemExtIETable) Table() s00.InterSystemMeasurementItemExtIEsValueExtensionTable {
	return func() s00.InterSystemMeasurementItemExtIEsValueExtensionTable {
		sealed := s00.InterSystemMeasurementItemExtIEsValueExtensionTable{}
		*s00.BridgeInterSystemMeasurementItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in InterSystemMeasurementItemExtIETable.
func (t InterSystemMeasurementItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (InterSystemMeasurementItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InterSystemMeasurementItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InterSystemMeasurementItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InterSystemMeasurementItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return InterSystemMeasurementItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.InterSystemMeasurementItemExtIEsValue {
			sealed := s05.InterSystemMeasurementItemExtIEsValue{}
			*s05.BridgeInterSystemMeasurementItemExtIEsValueFieldId(&sealed) = id
			*s05.BridgeInterSystemMeasurementItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeInterSystemMeasurementItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type InterSystemMeasurementParametersExtIETable struct{}

func InterSystemMeasurementParametersExtIEs() InterSystemMeasurementParametersExtIETable {
	return InterSystemMeasurementParametersExtIETable{}
}

// ID returns the ASN.1 object-set identity of InterSystemMeasurementParametersExtIETable.
func (InterSystemMeasurementParametersExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "InterSystemMeasurementParameters-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by InterSystemMeasurementParametersExtIETable.
func (InterSystemMeasurementParametersExtIETable) Table() s00.InterSystemMeasurementParametersExtIEsValueExtensionTable {
	return func() s00.InterSystemMeasurementParametersExtIEsValueExtensionTable {
		sealed := s00.InterSystemMeasurementParametersExtIEsValueExtensionTable{}
		*s00.BridgeInterSystemMeasurementParametersExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in InterSystemMeasurementParametersExtIETable.
func (t InterSystemMeasurementParametersExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (InterSystemMeasurementParametersExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InterSystemMeasurementParametersExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InterSystemMeasurementParametersExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InterSystemMeasurementParametersExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return InterSystemMeasurementParametersExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.InterSystemMeasurementParametersExtIEsValue {
			sealed := s05.InterSystemMeasurementParametersExtIEsValue{}
			*s05.BridgeInterSystemMeasurementParametersExtIEsValueFieldId(&sealed) = id
			*s05.BridgeInterSystemMeasurementParametersExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeInterSystemMeasurementParametersExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type IntersystemMeasurementConfigurationExtIETable struct{}

func IntersystemMeasurementConfigurationExtIEs() IntersystemMeasurementConfigurationExtIETable {
	return IntersystemMeasurementConfigurationExtIETable{}
}

// ID returns the ASN.1 object-set identity of IntersystemMeasurementConfigurationExtIETable.
func (IntersystemMeasurementConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IntersystemMeasurementConfiguration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by IntersystemMeasurementConfigurationExtIETable.
func (IntersystemMeasurementConfigurationExtIETable) Table() s00.IntersystemMeasurementConfigurationExtIEsValueExtensionTable {
	return func() s00.IntersystemMeasurementConfigurationExtIEsValueExtensionTable {
		sealed := s00.IntersystemMeasurementConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeIntersystemMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in IntersystemMeasurementConfigurationExtIETable.
func (t IntersystemMeasurementConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (IntersystemMeasurementConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return IntersystemMeasurementConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return IntersystemMeasurementConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return IntersystemMeasurementConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return IntersystemMeasurementConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.IntersystemMeasurementConfigurationExtIEsValue {
			sealed := s05.IntersystemMeasurementConfigurationExtIEsValue{}
			*s05.BridgeIntersystemMeasurementConfigurationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeIntersystemMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeIntersystemMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type LAIExtIETable struct{}

func LAIExtIEs() LAIExtIETable { return LAIExtIETable{} }

// ID returns the ASN.1 object-set identity of LAIExtIETable.
func (LAIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LAI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LAIExtIETable.
func (LAIExtIETable) Table() s00.LAIExtIEsValueExtensionTable {
	return func() s00.LAIExtIEsValueExtensionTable {
		sealed := s00.LAIExtIEsValueExtensionTable{}
		*s00.BridgeLAIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LAIExtIETable.
func (t LAIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (LAIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LAIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LAIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LAIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return LAIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.LAIExtIEsValue {
			sealed := s05.LAIExtIEsValue{}
			*s05.BridgeLAIExtIEsValueFieldId(&sealed) = id
			*s05.BridgeLAIExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeLAIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type LTENTNTAIInformationExtIETable struct{}

func LTENTNTAIInformationExtIEs() LTENTNTAIInformationExtIETable {
	return LTENTNTAIInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of LTENTNTAIInformationExtIETable.
func (LTENTNTAIInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LTENTNTAIInformationExtIETable.
func (LTENTNTAIInformationExtIETable) Table() s00.LTENTNTAIInformationExtIEsValueExtensionTable {
	return func() s00.LTENTNTAIInformationExtIEsValueExtensionTable {
		sealed := s00.LTENTNTAIInformationExtIEsValueExtensionTable{}
		*s00.BridgeLTENTNTAIInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LTENTNTAIInformationExtIETable.
func (t LTENTNTAIInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (LTENTNTAIInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LTENTNTAIInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LTENTNTAIInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LTENTNTAIInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return LTENTNTAIInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.LTENTNTAIInformationExtIEsValue {
			sealed := s05.LTENTNTAIInformationExtIEsValue{}
			*s05.BridgeLTENTNTAIInformationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeLTENTNTAIInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeLTENTNTAIInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type LastVisitedPSCellInformationExtIETable struct{}

func LastVisitedPSCellInformationExtIEs() LastVisitedPSCellInformationExtIETable {
	return LastVisitedPSCellInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of LastVisitedPSCellInformationExtIETable.
func (LastVisitedPSCellInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LastVisitedPSCellInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LastVisitedPSCellInformationExtIETable.
func (LastVisitedPSCellInformationExtIETable) Table() s00.LastVisitedPSCellInformationExtIEsValueExtensionTable {
	return func() s00.LastVisitedPSCellInformationExtIEsValueExtensionTable {
		sealed := s00.LastVisitedPSCellInformationExtIEsValueExtensionTable{}
		*s00.BridgeLastVisitedPSCellInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LastVisitedPSCellInformationExtIETable.
func (t LastVisitedPSCellInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (LastVisitedPSCellInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LastVisitedPSCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LastVisitedPSCellInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LastVisitedPSCellInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return LastVisitedPSCellInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.LastVisitedPSCellInformationExtIEsValue {
			sealed := s05.LastVisitedPSCellInformationExtIEsValue{}
			*s05.BridgeLastVisitedPSCellInformationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeLastVisitedPSCellInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeLastVisitedPSCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ListeningSubframePatternExtIETable struct{}

func ListeningSubframePatternExtIEs() ListeningSubframePatternExtIETable {
	return ListeningSubframePatternExtIETable{}
}

// ID returns the ASN.1 object-set identity of ListeningSubframePatternExtIETable.
func (ListeningSubframePatternExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ListeningSubframePattern-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ListeningSubframePatternExtIETable.
func (ListeningSubframePatternExtIETable) Table() s00.ListeningSubframePatternExtIEsValueExtensionTable {
	return func() s00.ListeningSubframePatternExtIEsValueExtensionTable {
		sealed := s00.ListeningSubframePatternExtIEsValueExtensionTable{}
		*s00.BridgeListeningSubframePatternExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ListeningSubframePatternExtIETable.
func (t ListeningSubframePatternExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ListeningSubframePatternExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ListeningSubframePatternExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ListeningSubframePatternExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ListeningSubframePatternExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ListeningSubframePatternExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.ListeningSubframePatternExtIEsValue {
			sealed := s05.ListeningSubframePatternExtIEsValue{}
			*s05.BridgeListeningSubframePatternExtIEsValueFieldId(&sealed) = id
			*s05.BridgeListeningSubframePatternExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeListeningSubframePatternExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type LoggedMBSFNMDTExtIETable struct{}

func LoggedMBSFNMDTExtIEs() LoggedMBSFNMDTExtIETable { return LoggedMBSFNMDTExtIETable{} }

// ID returns the ASN.1 object-set identity of LoggedMBSFNMDTExtIETable.
func (LoggedMBSFNMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMBSFNMDT-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LoggedMBSFNMDTExtIETable.
func (LoggedMBSFNMDTExtIETable) Table() s00.LoggedMBSFNMDTExtIEsValueExtensionTable {
	return func() s00.LoggedMBSFNMDTExtIEsValueExtensionTable {
		sealed := s00.LoggedMBSFNMDTExtIEsValueExtensionTable{}
		*s00.BridgeLoggedMBSFNMDTExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LoggedMBSFNMDTExtIETable.
func (t LoggedMBSFNMDTExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (LoggedMBSFNMDTExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LoggedMBSFNMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LoggedMBSFNMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LoggedMBSFNMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return LoggedMBSFNMDTExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.LoggedMBSFNMDTExtIEsValue {
			sealed := s05.LoggedMBSFNMDTExtIEsValue{}
			*s05.BridgeLoggedMBSFNMDTExtIEsValueFieldId(&sealed) = id
			*s05.BridgeLoggedMBSFNMDTExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeLoggedMBSFNMDTExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type M1PeriodicReportingExtIETable struct{}

func M1PeriodicReportingExtIEs() M1PeriodicReportingExtIETable {
	return M1PeriodicReportingExtIETable{}
}

// ID returns the ASN.1 object-set identity of M1PeriodicReportingExtIETable.
func (M1PeriodicReportingExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M1PeriodicReporting-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by M1PeriodicReportingExtIETable.
func (M1PeriodicReportingExtIETable) Table() s00.M1PeriodicReportingExtIEsValueExtensionTable {
	return func() s00.M1PeriodicReportingExtIEsValueExtensionTable {
		sealed := s00.M1PeriodicReportingExtIEsValueExtensionTable{}
		*s00.BridgeM1PeriodicReportingExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in M1PeriodicReportingExtIETable.
func (t M1PeriodicReportingExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (M1PeriodicReportingExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return M1PeriodicReportingExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return M1PeriodicReportingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return M1PeriodicReportingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return M1PeriodicReportingExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.M1PeriodicReportingExtIEsValue {
			sealed := s05.M1PeriodicReportingExtIEsValue{}
			*s05.BridgeM1PeriodicReportingExtIEsValueFieldId(&sealed) = id
			*s05.BridgeM1PeriodicReportingExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeM1PeriodicReportingExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type M1ThresholdEventA2ExtIETable struct{}

func M1ThresholdEventA2ExtIEs() M1ThresholdEventA2ExtIETable { return M1ThresholdEventA2ExtIETable{} }

// ID returns the ASN.1 object-set identity of M1ThresholdEventA2ExtIETable.
func (M1ThresholdEventA2ExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M1ThresholdEventA2-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by M1ThresholdEventA2ExtIETable.
func (M1ThresholdEventA2ExtIETable) Table() s00.M1ThresholdEventA2ExtIEsValueExtensionTable {
	return func() s00.M1ThresholdEventA2ExtIEsValueExtensionTable {
		sealed := s00.M1ThresholdEventA2ExtIEsValueExtensionTable{}
		*s00.BridgeM1ThresholdEventA2ExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in M1ThresholdEventA2ExtIETable.
func (t M1ThresholdEventA2ExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (M1ThresholdEventA2ExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return M1ThresholdEventA2ExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return M1ThresholdEventA2ExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return M1ThresholdEventA2ExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return M1ThresholdEventA2ExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.M1ThresholdEventA2ExtIEsValue {
			sealed := s05.M1ThresholdEventA2ExtIEsValue{}
			*s05.BridgeM1ThresholdEventA2ExtIEsValueFieldId(&sealed) = id
			*s05.BridgeM1ThresholdEventA2ExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeM1ThresholdEventA2ExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type M3ConfigurationExtIETable struct{}

func M3ConfigurationExtIEs() M3ConfigurationExtIETable { return M3ConfigurationExtIETable{} }

// ID returns the ASN.1 object-set identity of M3ConfigurationExtIETable.
func (M3ConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M3Configuration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by M3ConfigurationExtIETable.
func (M3ConfigurationExtIETable) Table() s00.M3ConfigurationExtIEsValueExtensionTable {
	return func() s00.M3ConfigurationExtIEsValueExtensionTable {
		sealed := s00.M3ConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeM3ConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in M3ConfigurationExtIETable.
func (t M3ConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (M3ConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return M3ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return M3ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return M3ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return M3ConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.M3ConfigurationExtIEsValue {
			sealed := s05.M3ConfigurationExtIEsValue{}
			*s05.BridgeM3ConfigurationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeM3ConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeM3ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type M4ConfigurationExtIETable struct{}

func M4ConfigurationExtIEs() M4ConfigurationExtIETable { return M4ConfigurationExtIETable{} }

// ID returns the ASN.1 object-set identity of M4ConfigurationExtIETable.
func (M4ConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M4Configuration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by M4ConfigurationExtIETable.
func (M4ConfigurationExtIETable) Table() s00.M4ConfigurationExtIEsValueExtensionTable {
	return func() s00.M4ConfigurationExtIEsValueExtensionTable {
		sealed := s00.M4ConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeM4ConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (M4ConfigurationExtIETable) infoM4ReportAmount() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: M4ConfigurationExtIEs().ID(), ID: s00.ProtocolExtensionID(346), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M4ReportAmountMDT"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M4Configuration-ExtIEs", Row: "id-M4ReportAmount"}}}
}

// M4ReportAmount returns the typed binding for the M4ReportAmount row of M4ConfigurationExtIETable.
func (t M4ConfigurationExtIETable) M4ReportAmount() M4ConfigurationExtIEsM4ReportAmountMDTExtBinding {
	return M4ConfigurationExtIEsM4ReportAmountMDTExtBinding{info: t.infoM4ReportAmount(), codec: func() s01.M4ReportAmountMDTValueCodec {
		sealed := s01.M4ReportAmountMDTValueCodec{}
		*s01.BridgeM4ReportAmountMDTValueCodecFieldPath(&sealed) = "M4ReportAmountMDT"
		*s01.BridgeM4ReportAmountMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M4ReportAmountMDT, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.M4ReportAmountMDT
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M4ReportAmountMDT")
			var zero s05.M4ConfigurationExtIEsValue
			decoded, err := s05.BridgeM4ConfigurationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(346), raw)
			if err != nil {
				var empty s00.M4ReportAmountMDT
				return empty, runtime.WrapDecodePath(err, "M4ReportAmountMDT")
			}
			value, ok := decoded.AsM4ReportAmount()
			if !ok {
				var empty s00.M4ReportAmountMDT
				return empty, fmt.Errorf("binding M4Configuration-ExtIEs.id-M4ReportAmount: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeM4ReportAmountMDTValueCodecFieldEncode(&sealed) = func(value s00.M4ReportAmountMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeM4ConfigurationExtIEsValueMethodEncodeFresh((func() s05.M4ConfigurationExtIEsValue {
				sealed := s05.M4ConfigurationExtIEsValue{}
				*s05.BridgeM4ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(346)
				*s05.BridgeM4ConfigurationExtIEsValueFieldRowM4ReportAmount(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeM4ReportAmountMDTValueCodecFieldCapture(&sealed) = func(v s00.M4ReportAmountMDT, options aper.DecodeState) (s00.M4ReportAmountMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APM4ReportAmountMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeM4ReportAmountMDTValueCodecFieldCompare(&sealed) = func(v s00.M4ReportAmountMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APM4ReportAmountMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeM4ReportAmountMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M4ReportAmountMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.M4ReportAmountMDT) s05.M4ConfigurationExtIEsValue {
			return func() s05.M4ConfigurationExtIEsValue {
				sealed := s05.M4ConfigurationExtIEsValue{}
				*s05.BridgeM4ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(346)
				*s05.BridgeM4ConfigurationExtIEsValueFieldRowM4ReportAmount(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.M4ConfigurationExtIEsValue) (*s00.M4ReportAmountMDT, bool) {
			return value.AsM4ReportAmount()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in M4ConfigurationExtIETable.
func (t M4ConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (M4ConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return M4ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(346):
		return M4ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M4ReportAmount requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return M4ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return M4ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return M4ConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.M4ConfigurationExtIEsValue {
			sealed := s05.M4ConfigurationExtIEsValue{}
			*s05.BridgeM4ConfigurationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeM4ConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeM4ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type M5ConfigurationExtIETable struct{}

func M5ConfigurationExtIEs() M5ConfigurationExtIETable { return M5ConfigurationExtIETable{} }

// ID returns the ASN.1 object-set identity of M5ConfigurationExtIETable.
func (M5ConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M5Configuration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by M5ConfigurationExtIETable.
func (M5ConfigurationExtIETable) Table() s00.M5ConfigurationExtIEsValueExtensionTable {
	return func() s00.M5ConfigurationExtIEsValueExtensionTable {
		sealed := s00.M5ConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeM5ConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (M5ConfigurationExtIETable) infoM5ReportAmount() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: M5ConfigurationExtIEs().ID(), ID: s00.ProtocolExtensionID(347), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M5ReportAmountMDT"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M5Configuration-ExtIEs", Row: "id-M5ReportAmount"}}}
}

// M5ReportAmount returns the typed binding for the M5ReportAmount row of M5ConfigurationExtIETable.
func (t M5ConfigurationExtIETable) M5ReportAmount() M5ConfigurationExtIEsM5ReportAmountMDTExtBinding {
	return M5ConfigurationExtIEsM5ReportAmountMDTExtBinding{info: t.infoM5ReportAmount(), codec: func() s01.M5ReportAmountMDTValueCodec {
		sealed := s01.M5ReportAmountMDTValueCodec{}
		*s01.BridgeM5ReportAmountMDTValueCodecFieldPath(&sealed) = "M5ReportAmountMDT"
		*s01.BridgeM5ReportAmountMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M5ReportAmountMDT, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.M5ReportAmountMDT
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M5ReportAmountMDT")
			var zero s05.M5ConfigurationExtIEsValue
			decoded, err := s05.BridgeM5ConfigurationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(347), raw)
			if err != nil {
				var empty s00.M5ReportAmountMDT
				return empty, runtime.WrapDecodePath(err, "M5ReportAmountMDT")
			}
			value, ok := decoded.AsM5ReportAmount()
			if !ok {
				var empty s00.M5ReportAmountMDT
				return empty, fmt.Errorf("binding M5Configuration-ExtIEs.id-M5ReportAmount: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeM5ReportAmountMDTValueCodecFieldEncode(&sealed) = func(value s00.M5ReportAmountMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeM5ConfigurationExtIEsValueMethodEncodeFresh((func() s05.M5ConfigurationExtIEsValue {
				sealed := s05.M5ConfigurationExtIEsValue{}
				*s05.BridgeM5ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(347)
				*s05.BridgeM5ConfigurationExtIEsValueFieldRowM5ReportAmount(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeM5ReportAmountMDTValueCodecFieldCapture(&sealed) = func(v s00.M5ReportAmountMDT, options aper.DecodeState) (s00.M5ReportAmountMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APM5ReportAmountMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeM5ReportAmountMDTValueCodecFieldCompare(&sealed) = func(v s00.M5ReportAmountMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APM5ReportAmountMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeM5ReportAmountMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M5ReportAmountMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.M5ReportAmountMDT) s05.M5ConfigurationExtIEsValue {
			return func() s05.M5ConfigurationExtIEsValue {
				sealed := s05.M5ConfigurationExtIEsValue{}
				*s05.BridgeM5ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(347)
				*s05.BridgeM5ConfigurationExtIEsValueFieldRowM5ReportAmount(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.M5ConfigurationExtIEsValue) (*s00.M5ReportAmountMDT, bool) {
			return value.AsM5ReportAmount()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in M5ConfigurationExtIETable.
func (t M5ConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (M5ConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return M5ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(347):
		return M5ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M5ReportAmount requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return M5ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return M5ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return M5ConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.M5ConfigurationExtIEsValue {
			sealed := s05.M5ConfigurationExtIEsValue{}
			*s05.BridgeM5ConfigurationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeM5ConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeM5ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type M6ConfigurationExtIETable struct{}

func M6ConfigurationExtIEs() M6ConfigurationExtIETable { return M6ConfigurationExtIETable{} }

// ID returns the ASN.1 object-set identity of M6ConfigurationExtIETable.
func (M6ConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M6Configuration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by M6ConfigurationExtIETable.
func (M6ConfigurationExtIETable) Table() s00.M6ConfigurationExtIEsValueExtensionTable {
	return func() s00.M6ConfigurationExtIEsValueExtensionTable {
		sealed := s00.M6ConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeM6ConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (M6ConfigurationExtIETable) infoM6ReportAmount() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: M6ConfigurationExtIEs().ID(), ID: s00.ProtocolExtensionID(348), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M6ReportAmountMDT"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M6Configuration-ExtIEs", Row: "id-M6ReportAmount"}}}
}

// M6ReportAmount returns the typed binding for the M6ReportAmount row of M6ConfigurationExtIETable.
func (t M6ConfigurationExtIETable) M6ReportAmount() M6ConfigurationExtIEsM6ReportAmountMDTExtBinding {
	return M6ConfigurationExtIEsM6ReportAmountMDTExtBinding{info: t.infoM6ReportAmount(), codec: func() s01.M6ReportAmountMDTValueCodec {
		sealed := s01.M6ReportAmountMDTValueCodec{}
		*s01.BridgeM6ReportAmountMDTValueCodecFieldPath(&sealed) = "M6ReportAmountMDT"
		*s01.BridgeM6ReportAmountMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M6ReportAmountMDT, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.M6ReportAmountMDT
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M6ReportAmountMDT")
			var zero s05.M6ConfigurationExtIEsValue
			decoded, err := s05.BridgeM6ConfigurationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(348), raw)
			if err != nil {
				var empty s00.M6ReportAmountMDT
				return empty, runtime.WrapDecodePath(err, "M6ReportAmountMDT")
			}
			value, ok := decoded.AsM6ReportAmount()
			if !ok {
				var empty s00.M6ReportAmountMDT
				return empty, fmt.Errorf("binding M6Configuration-ExtIEs.id-M6ReportAmount: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeM6ReportAmountMDTValueCodecFieldEncode(&sealed) = func(value s00.M6ReportAmountMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeM6ConfigurationExtIEsValueMethodEncodeFresh((func() s05.M6ConfigurationExtIEsValue {
				sealed := s05.M6ConfigurationExtIEsValue{}
				*s05.BridgeM6ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(348)
				*s05.BridgeM6ConfigurationExtIEsValueFieldRowM6ReportAmount(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeM6ReportAmountMDTValueCodecFieldCapture(&sealed) = func(v s00.M6ReportAmountMDT, options aper.DecodeState) (s00.M6ReportAmountMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APM6ReportAmountMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeM6ReportAmountMDTValueCodecFieldCompare(&sealed) = func(v s00.M6ReportAmountMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APM6ReportAmountMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeM6ReportAmountMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M6ReportAmountMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.M6ReportAmountMDT) s05.M6ConfigurationExtIEsValue {
			return func() s05.M6ConfigurationExtIEsValue {
				sealed := s05.M6ConfigurationExtIEsValue{}
				*s05.BridgeM6ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(348)
				*s05.BridgeM6ConfigurationExtIEsValueFieldRowM6ReportAmount(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.M6ConfigurationExtIEsValue) (*s00.M6ReportAmountMDT, bool) {
			return value.AsM6ReportAmount()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in M6ConfigurationExtIETable.
func (t M6ConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (M6ConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return M6ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(348):
		return M6ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M6ReportAmount requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return M6ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return M6ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return M6ConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.M6ConfigurationExtIEsValue {
			sealed := s05.M6ConfigurationExtIEsValue{}
			*s05.BridgeM6ConfigurationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeM6ConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeM6ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type M7ConfigurationExtIETable struct{}

func M7ConfigurationExtIEs() M7ConfigurationExtIETable { return M7ConfigurationExtIETable{} }

// ID returns the ASN.1 object-set identity of M7ConfigurationExtIETable.
func (M7ConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M7Configuration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by M7ConfigurationExtIETable.
func (M7ConfigurationExtIETable) Table() s00.M7ConfigurationExtIEsValueExtensionTable {
	return func() s00.M7ConfigurationExtIEsValueExtensionTable {
		sealed := s00.M7ConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeM7ConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (M7ConfigurationExtIETable) infoM7ReportAmount() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: M7ConfigurationExtIEs().ID(), ID: s00.ProtocolExtensionID(349), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M7ReportAmountMDT"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M7Configuration-ExtIEs", Row: "id-M7ReportAmount"}}}
}

// M7ReportAmount returns the typed binding for the M7ReportAmount row of M7ConfigurationExtIETable.
func (t M7ConfigurationExtIETable) M7ReportAmount() M7ConfigurationExtIEsM7ReportAmountMDTExtBinding {
	return M7ConfigurationExtIEsM7ReportAmountMDTExtBinding{info: t.infoM7ReportAmount(), codec: func() s01.M7ReportAmountMDTValueCodec {
		sealed := s01.M7ReportAmountMDTValueCodec{}
		*s01.BridgeM7ReportAmountMDTValueCodecFieldPath(&sealed) = "M7ReportAmountMDT"
		*s01.BridgeM7ReportAmountMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M7ReportAmountMDT, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.M7ReportAmountMDT
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M7ReportAmountMDT")
			var zero s05.M7ConfigurationExtIEsValue
			decoded, err := s05.BridgeM7ConfigurationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(349), raw)
			if err != nil {
				var empty s00.M7ReportAmountMDT
				return empty, runtime.WrapDecodePath(err, "M7ReportAmountMDT")
			}
			value, ok := decoded.AsM7ReportAmount()
			if !ok {
				var empty s00.M7ReportAmountMDT
				return empty, fmt.Errorf("binding M7Configuration-ExtIEs.id-M7ReportAmount: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeM7ReportAmountMDTValueCodecFieldEncode(&sealed) = func(value s00.M7ReportAmountMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeM7ConfigurationExtIEsValueMethodEncodeFresh((func() s05.M7ConfigurationExtIEsValue {
				sealed := s05.M7ConfigurationExtIEsValue{}
				*s05.BridgeM7ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(349)
				*s05.BridgeM7ConfigurationExtIEsValueFieldRowM7ReportAmount(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeM7ReportAmountMDTValueCodecFieldCapture(&sealed) = func(v s00.M7ReportAmountMDT, options aper.DecodeState) (s00.M7ReportAmountMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APM7ReportAmountMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeM7ReportAmountMDTValueCodecFieldCompare(&sealed) = func(v s00.M7ReportAmountMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APM7ReportAmountMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeM7ReportAmountMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M7ReportAmountMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.M7ReportAmountMDT) s05.M7ConfigurationExtIEsValue {
			return func() s05.M7ConfigurationExtIEsValue {
				sealed := s05.M7ConfigurationExtIEsValue{}
				*s05.BridgeM7ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(349)
				*s05.BridgeM7ConfigurationExtIEsValueFieldRowM7ReportAmount(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s05.M7ConfigurationExtIEsValue) (*s00.M7ReportAmountMDT, bool) {
			return value.AsM7ReportAmount()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in M7ConfigurationExtIETable.
func (t M7ConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (M7ConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return M7ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(349):
		return M7ConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M7ReportAmount requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return M7ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return M7ConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return M7ConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.M7ConfigurationExtIEsValue {
			sealed := s05.M7ConfigurationExtIEsValue{}
			*s05.BridgeM7ConfigurationExtIEsValueFieldId(&sealed) = id
			*s05.BridgeM7ConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeM7ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type MBSFNResultToLogInfoExtIETable struct{}

func MBSFNResultToLogInfoExtIEs() MBSFNResultToLogInfoExtIETable {
	return MBSFNResultToLogInfoExtIETable{}
}

// ID returns the ASN.1 object-set identity of MBSFNResultToLogInfoExtIETable.
func (MBSFNResultToLogInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MBSFN-ResultToLogInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MBSFNResultToLogInfoExtIETable.
func (MBSFNResultToLogInfoExtIETable) Table() s00.MBSFNResultToLogInfoExtIEsValueExtensionTable {
	return func() s00.MBSFNResultToLogInfoExtIEsValueExtensionTable {
		sealed := s00.MBSFNResultToLogInfoExtIEsValueExtensionTable{}
		*s00.BridgeMBSFNResultToLogInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MBSFNResultToLogInfoExtIETable.
func (t MBSFNResultToLogInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (MBSFNResultToLogInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MBSFNResultToLogInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MBSFNResultToLogInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MBSFNResultToLogInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return MBSFNResultToLogInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s05.MBSFNResultToLogInfoExtIEsValue {
			sealed := s05.MBSFNResultToLogInfoExtIEsValue{}
			*s05.BridgeMBSFNResultToLogInfoExtIEsValueFieldId(&sealed) = id
			*s05.BridgeMBSFNResultToLogInfoExtIEsValueFieldOpaque(&sealed) = opaque
			*s05.BridgeMBSFNResultToLogInfoExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type HandoverSuccessIETable struct{}

func HandoverSuccessIEs() HandoverSuccessIETable { return HandoverSuccessIETable{} }

// ID returns the ASN.1 object-set identity of HandoverSuccessIETable.
func (HandoverSuccessIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverSuccessIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverSuccessIETable.
func (HandoverSuccessIETable) Table() s00.HandoverSuccessIEValueIETable {
	return func() s00.HandoverSuccessIEValueIETable {
		sealed := s00.HandoverSuccessIEValueIETable{}
		*s00.BridgeHandoverSuccessIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverSuccessIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverSuccessIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverSuccessIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverSuccessIETable.
func (t HandoverSuccessIETable) MMEUES1APID() HandoverSuccessMMEUES1APIDIEBinding {
	return HandoverSuccessMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverSuccessIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverSuccessIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverSuccessIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverSuccessIEValue {
			return HandoverSuccessIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverSuccessIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverSuccessIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverSuccessIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverSuccessIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverSuccessIETable.
func (t HandoverSuccessIETable) ENBUES1APID() HandoverSuccessENBUES1APIDIEBinding {
	return HandoverSuccessENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero HandoverSuccessIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverSuccessIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverSuccessIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverSuccessIEValue {
			return HandoverSuccessIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverSuccessIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverSuccessIETable.
func (t HandoverSuccessIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverSuccessIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverSuccessIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverSuccessIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverSuccessIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverSuccessIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverSuccessIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverSuccessIEField{Id: id, Criticality: criticality, Value: HandoverSuccessIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ExtendedBitRateCodec binds the complete APER value type.
func ExtendedBitRateCodec() s00.ExtendedBitRateValueCodec {
	return GBRQosInformationExtIEs().ExtendedERABMaximumBitrateDL().Codec()
}

// HFNCodec binds the complete source value type.
func HFNCodec() s01.HFNValueCodec {
	return func() s01.HFNValueCodec {
		sealed := s01.HFNValueCodec{}
		*s01.BridgeHFNValueCodecFieldPath(&sealed) = "HFN"
		*s01.BridgeHFNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HFN, error) {
			var zero s00.HFN
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HFN, error) {
				var v struct{ Value s00.HFN }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HFN(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HFN"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeHFNValueCodecFieldEncode(&sealed) = func(value s00.HFN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HFN, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HFN }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false); err != nil {
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
		*s01.BridgeHFNValueCodecFieldCapture(&sealed) = func(v s00.HFN, options aper.DecodeState) (s00.HFN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHFN(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s01.BridgeHFNValueCodecFieldCompare(&sealed) = func(v s00.HFN, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHFN(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeHFNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HFN"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HFNModifiedCodec binds the complete source value type.
func HFNModifiedCodec() s01.HFNModifiedValueCodec {
	return func() s01.HFNModifiedValueCodec {
		sealed := s01.HFNModifiedValueCodec{}
		*s01.BridgeHFNModifiedValueCodecFieldPath(&sealed) = "HFNModified"
		*s01.BridgeHFNModifiedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HFNModified, error) {
			var zero s00.HFNModified
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HFNModified, error) {
				var v struct{ Value s00.HFNModified }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(131071), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HFNModified(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HFNModified"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeHFNModifiedValueCodecFieldEncode(&sealed) = func(value s00.HFNModified, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HFNModified, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HFNModified }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(131071), false); err != nil {
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
		*s01.BridgeHFNModifiedValueCodecFieldCapture(&sealed) = func(v s00.HFNModified, options aper.DecodeState) (s00.HFNModified, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHFNModified(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHFNModifiedValueCodecFieldCompare(&sealed) = func(v s00.HFNModified, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHFNModified(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeHFNModifiedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HFNModified"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HFNforPDCPSNlength18Codec binds the complete source value type.
func HFNforPDCPSNlength18Codec() s01.HFNforPDCPSNlength18ValueCodec {
	return func() s01.HFNforPDCPSNlength18ValueCodec {
		sealed := s01.HFNforPDCPSNlength18ValueCodec{}
		*s01.BridgeHFNforPDCPSNlength18ValueCodecFieldPath(&sealed) = "HFNforPDCPSNlength18"
		*s01.BridgeHFNforPDCPSNlength18ValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HFNforPDCPSNlength18, error) {
			var zero s00.HFNforPDCPSNlength18
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HFNforPDCPSNlength18, error) {
				var v struct{ Value s00.HFNforPDCPSNlength18 }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16383), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HFNforPDCPSNlength18(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HFNforPDCPSNlength18"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeHFNforPDCPSNlength18ValueCodecFieldEncode(&sealed) = func(value s00.HFNforPDCPSNlength18, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HFNforPDCPSNlength18, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HFNforPDCPSNlength18 }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16383), false); err != nil {
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
		*s01.BridgeHFNforPDCPSNlength18ValueCodecFieldCapture(&sealed) = func(v s00.HFNforPDCPSNlength18, options aper.DecodeState) (s00.HFNforPDCPSNlength18, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHFNforPDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHFNforPDCPSNlength18ValueCodecFieldCompare(&sealed) = func(v s00.HFNforPDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHFNforPDCPSNlength18(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeHFNforPDCPSNlength18ValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HFNforPDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverWindowDurationCodec binds the complete source value type.
func HandoverWindowDurationCodec() s01.HandoverWindowDurationValueCodec {
	return func() s01.HandoverWindowDurationValueCodec {
		sealed := s01.HandoverWindowDurationValueCodec{}
		*s01.BridgeHandoverWindowDurationValueCodecFieldPath(&sealed) = "HandoverWindowDuration"
		*s01.BridgeHandoverWindowDurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverWindowDuration, error) {
			var zero s00.HandoverWindowDuration
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HandoverWindowDuration, error) {
				var v struct{ Value s00.HandoverWindowDuration }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(6000), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HandoverWindowDuration(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverWindowDuration"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeHandoverWindowDurationValueCodecFieldEncode(&sealed) = func(value s00.HandoverWindowDuration, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HandoverWindowDuration, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HandoverWindowDuration }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(6000), false); err != nil {
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
		*s01.BridgeHandoverWindowDurationValueCodecFieldCapture(&sealed) = func(v s00.HandoverWindowDuration, options aper.DecodeState) (s00.HandoverWindowDuration, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHandoverWindowDuration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHandoverWindowDurationValueCodecFieldCompare(&sealed) = func(v s00.HandoverWindowDuration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHandoverWindowDuration(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeHandoverWindowDurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverWindowDuration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverWindowStartCodec binds the complete source value type.
func HandoverWindowStartCodec() s01.HandoverWindowStartValueCodec {
	return func() s01.HandoverWindowStartValueCodec {
		sealed := s01.HandoverWindowStartValueCodec{}
		*s01.BridgeHandoverWindowStartValueCodecFieldPath(&sealed) = "HandoverWindowStart"
		*s01.BridgeHandoverWindowStartValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverWindowStart, error) {
			var zero s00.HandoverWindowStart
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HandoverWindowStart, error) {
				var v struct{ Value s00.HandoverWindowStart }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HandoverWindowStart(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverWindowStart"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeHandoverWindowStartValueCodecFieldEncode(&sealed) = func(value s00.HandoverWindowStart, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HandoverWindowStart, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HandoverWindowStart }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false); err != nil {
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
		*s01.BridgeHandoverWindowStartValueCodecFieldCapture(&sealed) = func(v s00.HandoverWindowStart, options aper.DecodeState) (s00.HandoverWindowStart, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHandoverWindowStart(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHandoverWindowStartValueCodecFieldCompare(&sealed) = func(v s00.HandoverWindowStart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHandoverWindowStart(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeHandoverWindowStartValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverWindowStart"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HysteresisCodec binds the complete source value type.
func HysteresisCodec() s01.HysteresisValueCodec {
	return func() s01.HysteresisValueCodec {
		sealed := s01.HysteresisValueCodec{}
		*s01.BridgeHysteresisValueCodecFieldPath(&sealed) = "Hysteresis"
		*s01.BridgeHysteresisValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Hysteresis, error) {
			var zero s00.Hysteresis
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.Hysteresis, error) {
				var v struct{ Value s00.Hysteresis }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(30), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.Hysteresis(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Hysteresis"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeHysteresisValueCodecFieldEncode(&sealed) = func(value s00.Hysteresis, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.Hysteresis, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.Hysteresis }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(30), false); err != nil {
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
		*s01.BridgeHysteresisValueCodecFieldCapture(&sealed) = func(v s00.Hysteresis, options aper.DecodeState) (s00.Hysteresis, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APHysteresis(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHysteresisValueCodecFieldCompare(&sealed) = func(v s00.Hysteresis, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHysteresis(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeHysteresisValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Hysteresis"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LPPaPDUCodec binds the complete APER value type.
func LPPaPDUCodec() s01.LPPaPDUValueCodec {
	return s09.DownlinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Codec()
}

// M4ReportAmountMDTCodec binds the complete APER value type.
func M4ReportAmountMDTCodec() s01.M4ReportAmountMDTValueCodec {
	return M4ConfigurationExtIEs().M4ReportAmount().Codec()
}

// M5ReportAmountMDTCodec binds the complete APER value type.
func M5ReportAmountMDTCodec() s01.M5ReportAmountMDTValueCodec {
	return M5ConfigurationExtIEs().M5ReportAmount().Codec()
}

// M6ReportAmountMDTCodec binds the complete APER value type.
func M6ReportAmountMDTCodec() s01.M6ReportAmountMDTValueCodec {
	return M6ConfigurationExtIEs().M6ReportAmount().Codec()
}

// M7ReportAmountMDTCodec binds the complete APER value type.
func M7ReportAmountMDTCodec() s01.M7ReportAmountMDTValueCodec {
	return M7ConfigurationExtIEs().M7ReportAmount().Codec()
}
func BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldCapture(v *GBRQosInformationExtIEsExtContainerValueCodec) *func(GBRQosInformationExtIEsExtContainer, aper.DecodeState) (GBRQosInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldCompare(v *GBRQosInformationExtIEsExtContainerValueCodec) *func(GBRQosInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldContext(v *GBRQosInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldDecode(v *GBRQosInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (GBRQosInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldEncode(v *GBRQosInformationExtIEsExtContainerValueCodec) *func(GBRQosInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldPath(v *GBRQosInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeGBRQosInformationExtIEsExtFieldFieldReplay(v *GBRQosInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeGBRQosInformationExtIEsExtFieldFieldWithoutReplay(v *GBRQosInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeGBRQosInformationExtIEsExtFieldMethodMarshalAPERTo(v *GBRQosInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGBRQosInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *GBRQosInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldCapture(v *GBRQosInformationExtIEsExtFieldValueCodec) *func(GBRQosInformationExtIEsExtField, aper.DecodeState) (GBRQosInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldCompare(v *GBRQosInformationExtIEsExtFieldValueCodec) *func(GBRQosInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldContext(v *GBRQosInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldDecode(v *GBRQosInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (GBRQosInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldEncode(v *GBRQosInformationExtIEsExtFieldValueCodec) *func(GBRQosInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldPath(v *GBRQosInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeGERANCellIDExtIEsExtContainerValueCodecFieldCapture(v *GERANCellIDExtIEsExtContainerValueCodec) *func(GERANCellIDExtIEsExtContainer, aper.DecodeState) (GERANCellIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeGERANCellIDExtIEsExtContainerValueCodecFieldCompare(v *GERANCellIDExtIEsExtContainerValueCodec) *func(GERANCellIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGERANCellIDExtIEsExtContainerValueCodecFieldContext(v *GERANCellIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGERANCellIDExtIEsExtContainerValueCodecFieldDecode(v *GERANCellIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (GERANCellIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeGERANCellIDExtIEsExtContainerValueCodecFieldEncode(v *GERANCellIDExtIEsExtContainerValueCodec) *func(GERANCellIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGERANCellIDExtIEsExtContainerValueCodecFieldPath(v *GERANCellIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeGERANCellIDExtIEsExtFieldFieldReplay(v *GERANCellIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeGERANCellIDExtIEsExtFieldFieldWithoutReplay(v *GERANCellIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeGERANCellIDExtIEsExtFieldMethodMarshalAPERTo(v *GERANCellIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGERANCellIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *GERANCellIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGERANCellIDExtIEsExtFieldValueCodecFieldCapture(v *GERANCellIDExtIEsExtFieldValueCodec) *func(GERANCellIDExtIEsExtField, aper.DecodeState) (GERANCellIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeGERANCellIDExtIEsExtFieldValueCodecFieldCompare(v *GERANCellIDExtIEsExtFieldValueCodec) *func(GERANCellIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGERANCellIDExtIEsExtFieldValueCodecFieldContext(v *GERANCellIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGERANCellIDExtIEsExtFieldValueCodecFieldDecode(v *GERANCellIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (GERANCellIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeGERANCellIDExtIEsExtFieldValueCodecFieldEncode(v *GERANCellIDExtIEsExtFieldValueCodec) *func(GERANCellIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGERANCellIDExtIEsExtFieldValueCodecFieldPath(v *GERANCellIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeGNBExtIEsExtContainerValueCodecFieldCapture(v *GNBExtIEsExtContainerValueCodec) *func(GNBExtIEsExtContainer, aper.DecodeState) (GNBExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeGNBExtIEsExtContainerValueCodecFieldCompare(v *GNBExtIEsExtContainerValueCodec) *func(GNBExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGNBExtIEsExtContainerValueCodecFieldContext(v *GNBExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGNBExtIEsExtContainerValueCodecFieldDecode(v *GNBExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (GNBExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeGNBExtIEsExtContainerValueCodecFieldEncode(v *GNBExtIEsExtContainerValueCodec) *func(GNBExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGNBExtIEsExtContainerValueCodecFieldPath(v *GNBExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeGNBExtIEsExtFieldFieldReplay(v *GNBExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeGNBExtIEsExtFieldFieldWithoutReplay(v *GNBExtIEsExtField) *bool   { return &v.withoutReplay }
func BridgeGNBExtIEsExtFieldMethodMarshalAPERTo(v *GNBExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGNBExtIEsExtFieldMethodUnmarshalAPERFrom(v *GNBExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGNBExtIEsExtFieldValueCodecFieldCapture(v *GNBExtIEsExtFieldValueCodec) *func(GNBExtIEsExtField, aper.DecodeState) (GNBExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeGNBExtIEsExtFieldValueCodecFieldCompare(v *GNBExtIEsExtFieldValueCodec) *func(GNBExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGNBExtIEsExtFieldValueCodecFieldContext(v *GNBExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGNBExtIEsExtFieldValueCodecFieldDecode(v *GNBExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (GNBExtIEsExtField, error) {
	return &v.decode
}
func BridgeGNBExtIEsExtFieldValueCodecFieldEncode(v *GNBExtIEsExtFieldValueCodec) *func(GNBExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGNBExtIEsExtFieldValueCodecFieldPath(v *GNBExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeGUMMEIExtIEsExtContainerValueCodecFieldCapture(v *GUMMEIExtIEsExtContainerValueCodec) *func(GUMMEIExtIEsExtContainer, aper.DecodeState) (GUMMEIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeGUMMEIExtIEsExtContainerValueCodecFieldCompare(v *GUMMEIExtIEsExtContainerValueCodec) *func(GUMMEIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGUMMEIExtIEsExtContainerValueCodecFieldContext(v *GUMMEIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGUMMEIExtIEsExtContainerValueCodecFieldDecode(v *GUMMEIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (GUMMEIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeGUMMEIExtIEsExtContainerValueCodecFieldEncode(v *GUMMEIExtIEsExtContainerValueCodec) *func(GUMMEIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGUMMEIExtIEsExtContainerValueCodecFieldPath(v *GUMMEIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeGUMMEIExtIEsExtFieldFieldReplay(v *GUMMEIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeGUMMEIExtIEsExtFieldFieldWithoutReplay(v *GUMMEIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeGUMMEIExtIEsExtFieldMethodMarshalAPERTo(v *GUMMEIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGUMMEIExtIEsExtFieldMethodUnmarshalAPERFrom(v *GUMMEIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGUMMEIExtIEsExtFieldValueCodecFieldCapture(v *GUMMEIExtIEsExtFieldValueCodec) *func(GUMMEIExtIEsExtField, aper.DecodeState) (GUMMEIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeGUMMEIExtIEsExtFieldValueCodecFieldCompare(v *GUMMEIExtIEsExtFieldValueCodec) *func(GUMMEIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGUMMEIExtIEsExtFieldValueCodecFieldContext(v *GUMMEIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGUMMEIExtIEsExtFieldValueCodecFieldDecode(v *GUMMEIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (GUMMEIExtIEsExtField, error) {
	return &v.decode
}
func BridgeGUMMEIExtIEsExtFieldValueCodecFieldEncode(v *GUMMEIExtIEsExtFieldValueCodec) *func(GUMMEIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGUMMEIExtIEsExtFieldValueCodecFieldPath(v *GUMMEIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldCapture(v *GlobalENBIDExtIEsExtContainerValueCodec) *func(GlobalENBIDExtIEsExtContainer, aper.DecodeState) (GlobalENBIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldCompare(v *GlobalENBIDExtIEsExtContainerValueCodec) *func(GlobalENBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldContext(v *GlobalENBIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldDecode(v *GlobalENBIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (GlobalENBIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldEncode(v *GlobalENBIDExtIEsExtContainerValueCodec) *func(GlobalENBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldPath(v *GlobalENBIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeGlobalENBIDExtIEsExtFieldFieldReplay(v *GlobalENBIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeGlobalENBIDExtIEsExtFieldFieldWithoutReplay(v *GlobalENBIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeGlobalENBIDExtIEsExtFieldMethodMarshalAPERTo(v *GlobalENBIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGlobalENBIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *GlobalENBIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldCapture(v *GlobalENBIDExtIEsExtFieldValueCodec) *func(GlobalENBIDExtIEsExtField, aper.DecodeState) (GlobalENBIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldCompare(v *GlobalENBIDExtIEsExtFieldValueCodec) *func(GlobalENBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldContext(v *GlobalENBIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldDecode(v *GlobalENBIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (GlobalENBIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldEncode(v *GlobalENBIDExtIEsExtFieldValueCodec) *func(GlobalENBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldPath(v *GlobalENBIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldCapture(v *GlobalEnGNBIDExtIEsExtContainerValueCodec) *func(GlobalEnGNBIDExtIEsExtContainer, aper.DecodeState) (GlobalEnGNBIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldCompare(v *GlobalEnGNBIDExtIEsExtContainerValueCodec) *func(GlobalEnGNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldContext(v *GlobalEnGNBIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldDecode(v *GlobalEnGNBIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (GlobalEnGNBIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldEncode(v *GlobalEnGNBIDExtIEsExtContainerValueCodec) *func(GlobalEnGNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldPath(v *GlobalEnGNBIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeGlobalEnGNBIDExtIEsExtFieldFieldReplay(v *GlobalEnGNBIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeGlobalEnGNBIDExtIEsExtFieldFieldWithoutReplay(v *GlobalEnGNBIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeGlobalEnGNBIDExtIEsExtFieldMethodMarshalAPERTo(v *GlobalEnGNBIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGlobalEnGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *GlobalEnGNBIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldCapture(v *GlobalEnGNBIDExtIEsExtFieldValueCodec) *func(GlobalEnGNBIDExtIEsExtField, aper.DecodeState) (GlobalEnGNBIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldCompare(v *GlobalEnGNBIDExtIEsExtFieldValueCodec) *func(GlobalEnGNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldContext(v *GlobalEnGNBIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldDecode(v *GlobalEnGNBIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (GlobalEnGNBIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldEncode(v *GlobalEnGNBIDExtIEsExtFieldValueCodec) *func(GlobalEnGNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldPath(v *GlobalEnGNBIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldCapture(v *GlobalGNBIDExtIEsExtContainerValueCodec) *func(GlobalGNBIDExtIEsExtContainer, aper.DecodeState) (GlobalGNBIDExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldCompare(v *GlobalGNBIDExtIEsExtContainerValueCodec) *func(GlobalGNBIDExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldContext(v *GlobalGNBIDExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldDecode(v *GlobalGNBIDExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (GlobalGNBIDExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldEncode(v *GlobalGNBIDExtIEsExtContainerValueCodec) *func(GlobalGNBIDExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldPath(v *GlobalGNBIDExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeGlobalGNBIDExtIEsExtFieldFieldReplay(v *GlobalGNBIDExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeGlobalGNBIDExtIEsExtFieldFieldWithoutReplay(v *GlobalGNBIDExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeGlobalGNBIDExtIEsExtFieldMethodMarshalAPERTo(v *GlobalGNBIDExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGlobalGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(v *GlobalGNBIDExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldCapture(v *GlobalGNBIDExtIEsExtFieldValueCodec) *func(GlobalGNBIDExtIEsExtField, aper.DecodeState) (GlobalGNBIDExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldCompare(v *GlobalGNBIDExtIEsExtFieldValueCodec) *func(GlobalGNBIDExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldContext(v *GlobalGNBIDExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldDecode(v *GlobalGNBIDExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (GlobalGNBIDExtIEsExtField, error) {
	return &v.decode
}
func BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldEncode(v *GlobalGNBIDExtIEsExtFieldValueCodec) *func(GlobalGNBIDExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldPath(v *GlobalGNBIDExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverSuccessIEContainerValueCodecFieldCapture(v *HandoverSuccessIEContainerValueCodec) *func(HandoverSuccessIEContainer, aper.DecodeState) (HandoverSuccessIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverSuccessIEContainerValueCodecFieldCompare(v *HandoverSuccessIEContainerValueCodec) *func(HandoverSuccessIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverSuccessIEContainerValueCodecFieldContext(v *HandoverSuccessIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverSuccessIEContainerValueCodecFieldDecode(v *HandoverSuccessIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverSuccessIEContainer, error) {
	return &v.decode
}
func BridgeHandoverSuccessIEContainerValueCodecFieldEncode(v *HandoverSuccessIEContainerValueCodec) *func(HandoverSuccessIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverSuccessIEContainerValueCodecFieldPath(v *HandoverSuccessIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverSuccessIEFieldFieldReplay(v *HandoverSuccessIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverSuccessIEFieldFieldWithoutReplay(v *HandoverSuccessIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(v *HandoverSuccessIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(v *HandoverSuccessIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverSuccessIEFieldValueCodecFieldCapture(v *HandoverSuccessIEFieldValueCodec) *func(HandoverSuccessIEField, aper.DecodeState) (HandoverSuccessIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverSuccessIEFieldValueCodecFieldCompare(v *HandoverSuccessIEFieldValueCodec) *func(HandoverSuccessIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverSuccessIEFieldValueCodecFieldContext(v *HandoverSuccessIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverSuccessIEFieldValueCodecFieldDecode(v *HandoverSuccessIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverSuccessIEField, error) {
	return &v.decode
}
func BridgeHandoverSuccessIEFieldValueCodecFieldEncode(v *HandoverSuccessIEFieldValueCodec) *func(HandoverSuccessIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverSuccessIEFieldValueCodecFieldPath(v *HandoverSuccessIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverSuccessIEValueERABIEContainerListValueCodec) *func(HandoverSuccessIEValueERABIEContainerList, aper.DecodeState) (HandoverSuccessIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverSuccessIEValueERABIEContainerListValueCodec) *func(HandoverSuccessIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldContext(v *HandoverSuccessIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverSuccessIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverSuccessIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverSuccessIEValueERABIEContainerListValueCodec) *func(HandoverSuccessIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldPath(v *HandoverSuccessIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverSuccessIEValueFieldId(v *HandoverSuccessIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverSuccessIEValueFieldIsOpaque(v *HandoverSuccessIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverSuccessIEValueFieldOpaque(v *HandoverSuccessIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverSuccessIEValueFieldRowENBUES1APID(v *HandoverSuccessIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverSuccessIEValueFieldRowMMEUES1APID(v *HandoverSuccessIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverSuccessIEValueMethodCaptureSemantics(v HandoverSuccessIEValue, a0 aper.SemanticCapture) HandoverSuccessIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverSuccessIEValueMethodCompareSemantics(v HandoverSuccessIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverSuccessIEValueMethodMatchesID(v HandoverSuccessIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverSuccessIEValueMethodRule(v HandoverSuccessIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverSuccessIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverSuccessIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverSuccessIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverSuccessIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverSuccessIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverSuccessIEValueProtocolIEContainerListValueCodec) *func(HandoverSuccessIEValueProtocolIEContainerList, aper.DecodeState) (HandoverSuccessIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverSuccessIEValueProtocolIEContainerListValueCodec) *func(HandoverSuccessIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverSuccessIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverSuccessIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverSuccessIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverSuccessIEValueProtocolIEContainerListValueCodec) *func(HandoverSuccessIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverSuccessIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldCapture(v *InformationForCECapableUEsExtIEsExtContainerValueCodec) *func(InformationForCECapableUEsExtIEsExtContainer, aper.DecodeState) (InformationForCECapableUEsExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldCompare(v *InformationForCECapableUEsExtIEsExtContainerValueCodec) *func(InformationForCECapableUEsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldContext(v *InformationForCECapableUEsExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldDecode(v *InformationForCECapableUEsExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (InformationForCECapableUEsExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldEncode(v *InformationForCECapableUEsExtIEsExtContainerValueCodec) *func(InformationForCECapableUEsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldPath(v *InformationForCECapableUEsExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInformationForCECapableUEsExtIEsExtFieldFieldReplay(v *InformationForCECapableUEsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeInformationForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v *InformationForCECapableUEsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeInformationForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(v *InformationForCECapableUEsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInformationForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(v *InformationForCECapableUEsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldCapture(v *InformationForCECapableUEsExtIEsExtFieldValueCodec) *func(InformationForCECapableUEsExtIEsExtField, aper.DecodeState) (InformationForCECapableUEsExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldCompare(v *InformationForCECapableUEsExtIEsExtFieldValueCodec) *func(InformationForCECapableUEsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldContext(v *InformationForCECapableUEsExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldDecode(v *InformationForCECapableUEsExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (InformationForCECapableUEsExtIEsExtField, error) {
	return &v.decode
}
func BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldEncode(v *InformationForCECapableUEsExtIEsExtFieldValueCodec) *func(InformationForCECapableUEsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldPath(v *InformationForCECapableUEsExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldCapture(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) *func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldCompare(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) *func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldContext(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldDecode(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldEncode(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) *func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldPath(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldReplay(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldWithoutReplay(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldCapture(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) *func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldCompare(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) *func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldContext(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldDecode(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, error) {
	return &v.decode
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldEncode(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) *func(InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldPath(v *InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldCapture(v *InterSystemMeasurementItemExtIEsExtContainerValueCodec) *func(InterSystemMeasurementItemExtIEsExtContainer, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldCompare(v *InterSystemMeasurementItemExtIEsExtContainerValueCodec) *func(InterSystemMeasurementItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldContext(v *InterSystemMeasurementItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldDecode(v *InterSystemMeasurementItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldEncode(v *InterSystemMeasurementItemExtIEsExtContainerValueCodec) *func(InterSystemMeasurementItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldPath(v *InterSystemMeasurementItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldFieldReplay(v *InterSystemMeasurementItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldFieldWithoutReplay(v *InterSystemMeasurementItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldMethodMarshalAPERTo(v *InterSystemMeasurementItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *InterSystemMeasurementItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldCapture(v *InterSystemMeasurementItemExtIEsExtFieldValueCodec) *func(InterSystemMeasurementItemExtIEsExtField, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldCompare(v *InterSystemMeasurementItemExtIEsExtFieldValueCodec) *func(InterSystemMeasurementItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldContext(v *InterSystemMeasurementItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldDecode(v *InterSystemMeasurementItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (InterSystemMeasurementItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldEncode(v *InterSystemMeasurementItemExtIEsExtFieldValueCodec) *func(InterSystemMeasurementItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldPath(v *InterSystemMeasurementItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldCapture(v *InterSystemMeasurementParametersExtIEsExtContainerValueCodec) *func(InterSystemMeasurementParametersExtIEsExtContainer, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldCompare(v *InterSystemMeasurementParametersExtIEsExtContainerValueCodec) *func(InterSystemMeasurementParametersExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldContext(v *InterSystemMeasurementParametersExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldDecode(v *InterSystemMeasurementParametersExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldEncode(v *InterSystemMeasurementParametersExtIEsExtContainerValueCodec) *func(InterSystemMeasurementParametersExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldPath(v *InterSystemMeasurementParametersExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldReplay(v *InterSystemMeasurementParametersExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldWithoutReplay(v *InterSystemMeasurementParametersExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodMarshalAPERTo(v *InterSystemMeasurementParametersExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodUnmarshalAPERFrom(v *InterSystemMeasurementParametersExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldCapture(v *InterSystemMeasurementParametersExtIEsExtFieldValueCodec) *func(InterSystemMeasurementParametersExtIEsExtField, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldCompare(v *InterSystemMeasurementParametersExtIEsExtFieldValueCodec) *func(InterSystemMeasurementParametersExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldContext(v *InterSystemMeasurementParametersExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldDecode(v *InterSystemMeasurementParametersExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (InterSystemMeasurementParametersExtIEsExtField, error) {
	return &v.decode
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldEncode(v *InterSystemMeasurementParametersExtIEsExtFieldValueCodec) *func(InterSystemMeasurementParametersExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldPath(v *InterSystemMeasurementParametersExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(v *IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) *func(IntersystemMeasurementConfigurationExtIEsExtContainer, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(v *IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) *func(IntersystemMeasurementConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(v *IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(v *IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(v *IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) *func(IntersystemMeasurementConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldPath(v *IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldReplay(v *IntersystemMeasurementConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v *IntersystemMeasurementConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *IntersystemMeasurementConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *IntersystemMeasurementConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(v *IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) *func(IntersystemMeasurementConfigurationExtIEsExtField, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(v *IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) *func(IntersystemMeasurementConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(v *IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(v *IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (IntersystemMeasurementConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(v *IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) *func(IntersystemMeasurementConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldPath(v *IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLAIExtIEsExtContainerValueCodecFieldCapture(v *LAIExtIEsExtContainerValueCodec) *func(LAIExtIEsExtContainer, aper.DecodeState) (LAIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLAIExtIEsExtContainerValueCodecFieldCompare(v *LAIExtIEsExtContainerValueCodec) *func(LAIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLAIExtIEsExtContainerValueCodecFieldContext(v *LAIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLAIExtIEsExtContainerValueCodecFieldDecode(v *LAIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (LAIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeLAIExtIEsExtContainerValueCodecFieldEncode(v *LAIExtIEsExtContainerValueCodec) *func(LAIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLAIExtIEsExtContainerValueCodecFieldPath(v *LAIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLAIExtIEsExtFieldFieldReplay(v *LAIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeLAIExtIEsExtFieldFieldWithoutReplay(v *LAIExtIEsExtField) *bool   { return &v.withoutReplay }
func BridgeLAIExtIEsExtFieldMethodMarshalAPERTo(v *LAIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLAIExtIEsExtFieldMethodUnmarshalAPERFrom(v *LAIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLAIExtIEsExtFieldValueCodecFieldCapture(v *LAIExtIEsExtFieldValueCodec) *func(LAIExtIEsExtField, aper.DecodeState) (LAIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeLAIExtIEsExtFieldValueCodecFieldCompare(v *LAIExtIEsExtFieldValueCodec) *func(LAIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLAIExtIEsExtFieldValueCodecFieldContext(v *LAIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLAIExtIEsExtFieldValueCodecFieldDecode(v *LAIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (LAIExtIEsExtField, error) {
	return &v.decode
}
func BridgeLAIExtIEsExtFieldValueCodecFieldEncode(v *LAIExtIEsExtFieldValueCodec) *func(LAIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLAIExtIEsExtFieldValueCodecFieldPath(v *LAIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldCapture(v *LTENTNTAIInformationExtIEsExtContainerValueCodec) *func(LTENTNTAIInformationExtIEsExtContainer, aper.DecodeState) (LTENTNTAIInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldCompare(v *LTENTNTAIInformationExtIEsExtContainerValueCodec) *func(LTENTNTAIInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldContext(v *LTENTNTAIInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldDecode(v *LTENTNTAIInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (LTENTNTAIInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldEncode(v *LTENTNTAIInformationExtIEsExtContainerValueCodec) *func(LTENTNTAIInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldPath(v *LTENTNTAIInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLTENTNTAIInformationExtIEsExtFieldFieldReplay(v *LTENTNTAIInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeLTENTNTAIInformationExtIEsExtFieldFieldWithoutReplay(v *LTENTNTAIInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeLTENTNTAIInformationExtIEsExtFieldMethodMarshalAPERTo(v *LTENTNTAIInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLTENTNTAIInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *LTENTNTAIInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldCapture(v *LTENTNTAIInformationExtIEsExtFieldValueCodec) *func(LTENTNTAIInformationExtIEsExtField, aper.DecodeState) (LTENTNTAIInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldCompare(v *LTENTNTAIInformationExtIEsExtFieldValueCodec) *func(LTENTNTAIInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldContext(v *LTENTNTAIInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldDecode(v *LTENTNTAIInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (LTENTNTAIInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldEncode(v *LTENTNTAIInformationExtIEsExtFieldValueCodec) *func(LTENTNTAIInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldPath(v *LTENTNTAIInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldCapture(v *LastVisitedPSCellInformationExtIEsExtContainerValueCodec) *func(LastVisitedPSCellInformationExtIEsExtContainer, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldCompare(v *LastVisitedPSCellInformationExtIEsExtContainerValueCodec) *func(LastVisitedPSCellInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldContext(v *LastVisitedPSCellInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldDecode(v *LastVisitedPSCellInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldEncode(v *LastVisitedPSCellInformationExtIEsExtContainerValueCodec) *func(LastVisitedPSCellInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldPath(v *LastVisitedPSCellInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldReplay(v *LastVisitedPSCellInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldWithoutReplay(v *LastVisitedPSCellInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodMarshalAPERTo(v *LastVisitedPSCellInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *LastVisitedPSCellInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldCapture(v *LastVisitedPSCellInformationExtIEsExtFieldValueCodec) *func(LastVisitedPSCellInformationExtIEsExtField, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldCompare(v *LastVisitedPSCellInformationExtIEsExtFieldValueCodec) *func(LastVisitedPSCellInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldContext(v *LastVisitedPSCellInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldDecode(v *LastVisitedPSCellInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (LastVisitedPSCellInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldEncode(v *LastVisitedPSCellInformationExtIEsExtFieldValueCodec) *func(LastVisitedPSCellInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldPath(v *LastVisitedPSCellInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldCapture(v *ListeningSubframePatternExtIEsExtContainerValueCodec) *func(ListeningSubframePatternExtIEsExtContainer, aper.DecodeState) (ListeningSubframePatternExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldCompare(v *ListeningSubframePatternExtIEsExtContainerValueCodec) *func(ListeningSubframePatternExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldContext(v *ListeningSubframePatternExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldDecode(v *ListeningSubframePatternExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ListeningSubframePatternExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldEncode(v *ListeningSubframePatternExtIEsExtContainerValueCodec) *func(ListeningSubframePatternExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldPath(v *ListeningSubframePatternExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeListeningSubframePatternExtIEsExtFieldFieldReplay(v *ListeningSubframePatternExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeListeningSubframePatternExtIEsExtFieldFieldWithoutReplay(v *ListeningSubframePatternExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeListeningSubframePatternExtIEsExtFieldMethodMarshalAPERTo(v *ListeningSubframePatternExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeListeningSubframePatternExtIEsExtFieldMethodUnmarshalAPERFrom(v *ListeningSubframePatternExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldCapture(v *ListeningSubframePatternExtIEsExtFieldValueCodec) *func(ListeningSubframePatternExtIEsExtField, aper.DecodeState) (ListeningSubframePatternExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldCompare(v *ListeningSubframePatternExtIEsExtFieldValueCodec) *func(ListeningSubframePatternExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldContext(v *ListeningSubframePatternExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldDecode(v *ListeningSubframePatternExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ListeningSubframePatternExtIEsExtField, error) {
	return &v.decode
}
func BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldEncode(v *ListeningSubframePatternExtIEsExtFieldValueCodec) *func(ListeningSubframePatternExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldPath(v *ListeningSubframePatternExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldCapture(v *LoggedMBSFNMDTExtIEsExtContainerValueCodec) *func(LoggedMBSFNMDTExtIEsExtContainer, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldCompare(v *LoggedMBSFNMDTExtIEsExtContainerValueCodec) *func(LoggedMBSFNMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldContext(v *LoggedMBSFNMDTExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldDecode(v *LoggedMBSFNMDTExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldEncode(v *LoggedMBSFNMDTExtIEsExtContainerValueCodec) *func(LoggedMBSFNMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldPath(v *LoggedMBSFNMDTExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldFieldReplay(v *LoggedMBSFNMDTExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldFieldWithoutReplay(v *LoggedMBSFNMDTExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldMethodMarshalAPERTo(v *LoggedMBSFNMDTExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldMethodUnmarshalAPERFrom(v *LoggedMBSFNMDTExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldCapture(v *LoggedMBSFNMDTExtIEsExtFieldValueCodec) *func(LoggedMBSFNMDTExtIEsExtField, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldCompare(v *LoggedMBSFNMDTExtIEsExtFieldValueCodec) *func(LoggedMBSFNMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldContext(v *LoggedMBSFNMDTExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldDecode(v *LoggedMBSFNMDTExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (LoggedMBSFNMDTExtIEsExtField, error) {
	return &v.decode
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldEncode(v *LoggedMBSFNMDTExtIEsExtFieldValueCodec) *func(LoggedMBSFNMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldPath(v *LoggedMBSFNMDTExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldCapture(v *M1PeriodicReportingExtIEsExtContainerValueCodec) *func(M1PeriodicReportingExtIEsExtContainer, aper.DecodeState) (M1PeriodicReportingExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldCompare(v *M1PeriodicReportingExtIEsExtContainerValueCodec) *func(M1PeriodicReportingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldContext(v *M1PeriodicReportingExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldDecode(v *M1PeriodicReportingExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (M1PeriodicReportingExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldEncode(v *M1PeriodicReportingExtIEsExtContainerValueCodec) *func(M1PeriodicReportingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldPath(v *M1PeriodicReportingExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM1PeriodicReportingExtIEsExtFieldFieldReplay(v *M1PeriodicReportingExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeM1PeriodicReportingExtIEsExtFieldFieldWithoutReplay(v *M1PeriodicReportingExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeM1PeriodicReportingExtIEsExtFieldMethodMarshalAPERTo(v *M1PeriodicReportingExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM1PeriodicReportingExtIEsExtFieldMethodUnmarshalAPERFrom(v *M1PeriodicReportingExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldCapture(v *M1PeriodicReportingExtIEsExtFieldValueCodec) *func(M1PeriodicReportingExtIEsExtField, aper.DecodeState) (M1PeriodicReportingExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldCompare(v *M1PeriodicReportingExtIEsExtFieldValueCodec) *func(M1PeriodicReportingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldContext(v *M1PeriodicReportingExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldDecode(v *M1PeriodicReportingExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (M1PeriodicReportingExtIEsExtField, error) {
	return &v.decode
}
func BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldEncode(v *M1PeriodicReportingExtIEsExtFieldValueCodec) *func(M1PeriodicReportingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldPath(v *M1PeriodicReportingExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldCapture(v *M1ThresholdEventA2ExtIEsExtContainerValueCodec) *func(M1ThresholdEventA2ExtIEsExtContainer, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldCompare(v *M1ThresholdEventA2ExtIEsExtContainerValueCodec) *func(M1ThresholdEventA2ExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldContext(v *M1ThresholdEventA2ExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldDecode(v *M1ThresholdEventA2ExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldEncode(v *M1ThresholdEventA2ExtIEsExtContainerValueCodec) *func(M1ThresholdEventA2ExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldPath(v *M1ThresholdEventA2ExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldFieldReplay(v *M1ThresholdEventA2ExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldFieldWithoutReplay(v *M1ThresholdEventA2ExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldMethodMarshalAPERTo(v *M1ThresholdEventA2ExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldMethodUnmarshalAPERFrom(v *M1ThresholdEventA2ExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldCapture(v *M1ThresholdEventA2ExtIEsExtFieldValueCodec) *func(M1ThresholdEventA2ExtIEsExtField, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldCompare(v *M1ThresholdEventA2ExtIEsExtFieldValueCodec) *func(M1ThresholdEventA2ExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldContext(v *M1ThresholdEventA2ExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldDecode(v *M1ThresholdEventA2ExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (M1ThresholdEventA2ExtIEsExtField, error) {
	return &v.decode
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldEncode(v *M1ThresholdEventA2ExtIEsExtFieldValueCodec) *func(M1ThresholdEventA2ExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldPath(v *M1ThresholdEventA2ExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldCapture(v *M3ConfigurationExtIEsExtContainerValueCodec) *func(M3ConfigurationExtIEsExtContainer, aper.DecodeState) (M3ConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldCompare(v *M3ConfigurationExtIEsExtContainerValueCodec) *func(M3ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldContext(v *M3ConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldDecode(v *M3ConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (M3ConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldEncode(v *M3ConfigurationExtIEsExtContainerValueCodec) *func(M3ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldPath(v *M3ConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM3ConfigurationExtIEsExtFieldFieldReplay(v *M3ConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeM3ConfigurationExtIEsExtFieldFieldWithoutReplay(v *M3ConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeM3ConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *M3ConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM3ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *M3ConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldCapture(v *M3ConfigurationExtIEsExtFieldValueCodec) *func(M3ConfigurationExtIEsExtField, aper.DecodeState) (M3ConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldCompare(v *M3ConfigurationExtIEsExtFieldValueCodec) *func(M3ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldContext(v *M3ConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldDecode(v *M3ConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (M3ConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldEncode(v *M3ConfigurationExtIEsExtFieldValueCodec) *func(M3ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldPath(v *M3ConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldCapture(v *M4ConfigurationExtIEsExtContainerValueCodec) *func(M4ConfigurationExtIEsExtContainer, aper.DecodeState) (M4ConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldCompare(v *M4ConfigurationExtIEsExtContainerValueCodec) *func(M4ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldContext(v *M4ConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldDecode(v *M4ConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (M4ConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldEncode(v *M4ConfigurationExtIEsExtContainerValueCodec) *func(M4ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldPath(v *M4ConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM4ConfigurationExtIEsExtFieldFieldReplay(v *M4ConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeM4ConfigurationExtIEsExtFieldFieldWithoutReplay(v *M4ConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeM4ConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *M4ConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM4ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *M4ConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldCapture(v *M4ConfigurationExtIEsExtFieldValueCodec) *func(M4ConfigurationExtIEsExtField, aper.DecodeState) (M4ConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldCompare(v *M4ConfigurationExtIEsExtFieldValueCodec) *func(M4ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldContext(v *M4ConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldDecode(v *M4ConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (M4ConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldEncode(v *M4ConfigurationExtIEsExtFieldValueCodec) *func(M4ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldPath(v *M4ConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldCapture(v *M5ConfigurationExtIEsExtContainerValueCodec) *func(M5ConfigurationExtIEsExtContainer, aper.DecodeState) (M5ConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldCompare(v *M5ConfigurationExtIEsExtContainerValueCodec) *func(M5ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldContext(v *M5ConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldDecode(v *M5ConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (M5ConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldEncode(v *M5ConfigurationExtIEsExtContainerValueCodec) *func(M5ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldPath(v *M5ConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM5ConfigurationExtIEsExtFieldFieldReplay(v *M5ConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeM5ConfigurationExtIEsExtFieldFieldWithoutReplay(v *M5ConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeM5ConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *M5ConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM5ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *M5ConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldCapture(v *M5ConfigurationExtIEsExtFieldValueCodec) *func(M5ConfigurationExtIEsExtField, aper.DecodeState) (M5ConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldCompare(v *M5ConfigurationExtIEsExtFieldValueCodec) *func(M5ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldContext(v *M5ConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldDecode(v *M5ConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (M5ConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldEncode(v *M5ConfigurationExtIEsExtFieldValueCodec) *func(M5ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldPath(v *M5ConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldCapture(v *M6ConfigurationExtIEsExtContainerValueCodec) *func(M6ConfigurationExtIEsExtContainer, aper.DecodeState) (M6ConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldCompare(v *M6ConfigurationExtIEsExtContainerValueCodec) *func(M6ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldContext(v *M6ConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldDecode(v *M6ConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (M6ConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldEncode(v *M6ConfigurationExtIEsExtContainerValueCodec) *func(M6ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldPath(v *M6ConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM6ConfigurationExtIEsExtFieldFieldReplay(v *M6ConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeM6ConfigurationExtIEsExtFieldFieldWithoutReplay(v *M6ConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeM6ConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *M6ConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM6ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *M6ConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldCapture(v *M6ConfigurationExtIEsExtFieldValueCodec) *func(M6ConfigurationExtIEsExtField, aper.DecodeState) (M6ConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldCompare(v *M6ConfigurationExtIEsExtFieldValueCodec) *func(M6ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldContext(v *M6ConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldDecode(v *M6ConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (M6ConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldEncode(v *M6ConfigurationExtIEsExtFieldValueCodec) *func(M6ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldPath(v *M6ConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldCapture(v *M7ConfigurationExtIEsExtContainerValueCodec) *func(M7ConfigurationExtIEsExtContainer, aper.DecodeState) (M7ConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldCompare(v *M7ConfigurationExtIEsExtContainerValueCodec) *func(M7ConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldContext(v *M7ConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldDecode(v *M7ConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (M7ConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldEncode(v *M7ConfigurationExtIEsExtContainerValueCodec) *func(M7ConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldPath(v *M7ConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM7ConfigurationExtIEsExtFieldFieldReplay(v *M7ConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeM7ConfigurationExtIEsExtFieldFieldWithoutReplay(v *M7ConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeM7ConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *M7ConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM7ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *M7ConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldCapture(v *M7ConfigurationExtIEsExtFieldValueCodec) *func(M7ConfigurationExtIEsExtField, aper.DecodeState) (M7ConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldCompare(v *M7ConfigurationExtIEsExtFieldValueCodec) *func(M7ConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldContext(v *M7ConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldDecode(v *M7ConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (M7ConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldEncode(v *M7ConfigurationExtIEsExtFieldValueCodec) *func(M7ConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldPath(v *M7ConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldCapture(v *MBSFNResultToLogInfoExtIEsExtContainerValueCodec) *func(MBSFNResultToLogInfoExtIEsExtContainer, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldCompare(v *MBSFNResultToLogInfoExtIEsExtContainerValueCodec) *func(MBSFNResultToLogInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldContext(v *MBSFNResultToLogInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldDecode(v *MBSFNResultToLogInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldEncode(v *MBSFNResultToLogInfoExtIEsExtContainerValueCodec) *func(MBSFNResultToLogInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldPath(v *MBSFNResultToLogInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldReplay(v *MBSFNResultToLogInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldWithoutReplay(v *MBSFNResultToLogInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodMarshalAPERTo(v *MBSFNResultToLogInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *MBSFNResultToLogInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldCapture(v *MBSFNResultToLogInfoExtIEsExtFieldValueCodec) *func(MBSFNResultToLogInfoExtIEsExtField, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldCompare(v *MBSFNResultToLogInfoExtIEsExtFieldValueCodec) *func(MBSFNResultToLogInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldContext(v *MBSFNResultToLogInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldDecode(v *MBSFNResultToLogInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (MBSFNResultToLogInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldEncode(v *MBSFNResultToLogInfoExtIEsExtFieldValueCodec) *func(MBSFNResultToLogInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldPath(v *MBSFNResultToLogInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldCodec(v *MMECPRelocationIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldGet(v *MMECPRelocationIndicationENBUES1APIDIEBinding) *func(*MMECPRelocationIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldInfo(v *MMECPRelocationIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldInject(v *MMECPRelocationIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) MMECPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeMMECPRelocationIndicationIEFieldFieldReplay(v *MMECPRelocationIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMECPRelocationIndicationIEFieldFieldWithoutReplay(v *MMECPRelocationIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(v *MMECPRelocationIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(v *MMECPRelocationIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMECPRelocationIndicationIEValueFieldId(v *MMECPRelocationIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMECPRelocationIndicationIEValueFieldIsOpaque(v *MMECPRelocationIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMECPRelocationIndicationIEValueFieldOpaque(v *MMECPRelocationIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMECPRelocationIndicationIEValueFieldRowENBUES1APID(v *MMECPRelocationIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeMMECPRelocationIndicationIEValueFieldRowMMEUES1APID(v *MMECPRelocationIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeMMECPRelocationIndicationIEValueMethodCaptureSemantics(v MMECPRelocationIndicationIEValue, a0 aper.SemanticCapture) MMECPRelocationIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMECPRelocationIndicationIEValueMethodCompareSemantics(v MMECPRelocationIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMECPRelocationIndicationIEValueMethodDecode(v MMECPRelocationIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMECPRelocationIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMECPRelocationIndicationIEValueMethodEncodeFresh(v MMECPRelocationIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMECPRelocationIndicationIEValueMethodMatchesID(v MMECPRelocationIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMECPRelocationIndicationIEValueMethodRule(v MMECPRelocationIndicationIEValue) aper.SourceRule {
	return v.rule()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *HandoverSuccessIEValue) Selected() (any, bool) {
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
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *MMECPRelocationIndicationIEValue) Selected() (any, bool) {
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
	}
	return nil, false
}
