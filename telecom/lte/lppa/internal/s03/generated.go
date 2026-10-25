// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s03 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s03

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementTerminationCommandIEContainer is ProtocolIE-Container {{E-CIDMeasurementTerminationCommand-IEs}} of TS 36.455: a list of ECIDMeasurementTerminationCommandIEField values.
type ECIDMeasurementTerminationCommandIEContainer []ECIDMeasurementTerminationCommandIEField

// ECIDMeasurementTerminationCommandIEField is ProtocolIE-Field {{E-CIDMeasurementTerminationCommand-IEs}} of TS 36.455: a field carrying a value of ECIDMeasurementTerminationCommandIEValue.
type ECIDMeasurementTerminationCommandIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.ECIDMeasurementTerminationCommandIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementTerminationCommandIEField) WithoutReplay() ECIDMeasurementTerminationCommandIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECIDMeasurementTerminationCommandIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementTerminationCommandIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeECIDMeasurementTerminationCommandIEValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ECIDMeasurementTerminationCommandIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementTerminationCommandIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.ECIDMeasurementTerminationCommandIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeECIDMeasurementTerminationCommandIEValueMethodReason(zero, v.Id), s02.BridgeECIDMeasurementTerminationCommandIEValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationExtIEsExtContainer is ProtocolExtensionContainer {{Assistance-Information-ExtIEs}} of TS 36.455: a list of AssistanceInformationExtIEsExtField values.
type AssistanceInformationExtIEsExtContainer []AssistanceInformationExtIEsExtField

// AssistanceInformationMetaDataExtIEsExtContainer is ProtocolExtensionContainer {{AssistanceInformationMetaData-ExtIEs}} of TS 36.455: a list of AssistanceInformationMetaDataExtIEsExtField values.
type AssistanceInformationMetaDataExtIEsExtContainer []AssistanceInformationMetaDataExtIEsExtField

// CriticalityDiagnosticsExtIEsExtContainer is ProtocolExtensionContainer {{CriticalityDiagnostics-ExtIEs}} of TS 36.455: a list of CriticalityDiagnosticsExtIEsExtField values.
type CriticalityDiagnosticsExtIEsExtContainer []CriticalityDiagnosticsExtIEsExtField

// ECGIExtIEsExtContainer is ProtocolExtensionContainer {{ECGI-ExtIEs}} of TS 36.455: a list of ECGIExtIEsExtField values.
type ECGIExtIEsExtContainer []ECGIExtIEsExtField

// InterRATMeasurementQuantitiesValueExtIEsExtContainer is ProtocolExtensionContainer {{InterRATMeasurementQuantitiesValue-ExtIEs}} of TS 36.455: a list of InterRATMeasurementQuantitiesValueExtIEsExtField values.
type InterRATMeasurementQuantitiesValueExtIEsExtContainer []InterRATMeasurementQuantitiesValueExtIEsExtField

// AddOTDOACellsExtIEsExtContainer is ProtocolExtensionContainer {{Add-OTDOACells-ExtIEs}} of TS 36.455: a list of AddOTDOACellsExtIEsExtField values.
type AddOTDOACellsExtIEsExtContainer []AddOTDOACellsExtIEsExtField

// AssistanceInformationFailureListExtIEsExtContainer is ProtocolExtensionContainer {{AssistanceInformationFailureList-ExtIEs}} of TS 36.455: a list of AssistanceInformationFailureListExtIEsExtField values.
type AssistanceInformationFailureListExtIEsExtContainer []AssistanceInformationFailureListExtIEsExtField

// CriticalityDiagnosticsIEListExtIEsExtContainer is ProtocolExtensionContainer {{CriticalityDiagnostics-IE-List-ExtIEs}} of TS 36.455: a list of CriticalityDiagnosticsIEListExtIEsExtField values.
type CriticalityDiagnosticsIEListExtIEsExtContainer []CriticalityDiagnosticsIEListExtIEsExtField

// AssistanceInformationExtIEsExtField is ProtocolExtensionField {{Assistance-Information-ExtIEs}} of TS 36.455: a field carrying a value of AssistanceInformationExtIEsValue.
type AssistanceInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.AssistanceInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationExtIEsExtField) WithoutReplay() AssistanceInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAssistanceInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAssistanceInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AssistanceInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AssistanceInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAssistanceInformationExtIEsValueMethodReason(zero, v.Id), s02.BridgeAssistanceInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeAssistanceInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationMetaDataExtIEsExtField is ProtocolExtensionField {{AssistanceInformationMetaData-ExtIEs}} of TS 36.455: a field carrying a value of AssistanceInformationMetaDataExtIEsValue.
type AssistanceInformationMetaDataExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.AssistanceInformationMetaDataExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationMetaDataExtIEsExtField) WithoutReplay() AssistanceInformationMetaDataExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationMetaDataExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationMetaDataExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AssistanceInformationMetaDataExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationMetaDataExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AssistanceInformationMetaDataExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodReason(zero, v.Id), s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsExtIEsExtField is ProtocolExtensionField {{CriticalityDiagnostics-ExtIEs}} of TS 36.455: a field carrying a value of CriticalityDiagnosticsExtIEsValue.
type CriticalityDiagnosticsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.CriticalityDiagnosticsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsExtIEsExtField) WithoutReplay() CriticalityDiagnosticsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *CriticalityDiagnosticsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.CriticalityDiagnosticsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeCriticalityDiagnosticsExtIEsValueMethodReason(zero, v.Id), s02.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECGIExtIEsExtField is ProtocolExtensionField {{ECGI-ExtIEs}} of TS 36.455: a field carrying a value of ECGIExtIEsValue.
type ECGIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.ECGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECGIExtIEsExtField) WithoutReplay() ECGIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECGIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECGIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeECGIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeECGIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ECGIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECGIExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.ECGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeECGIExtIEsValueMethodReason(zero, v.Id), s02.BridgeECGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeECGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// InterRATMeasurementQuantitiesValueExtIEsExtField is ProtocolExtensionField {{InterRATMeasurementQuantitiesValue-ExtIEs}} of TS 36.455: a field carrying a value of InterRATMeasurementQuantitiesValueExtIEsValue.
type InterRATMeasurementQuantitiesValueExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.InterRATMeasurementQuantitiesValueExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasurementQuantitiesValueExtIEsExtField) WithoutReplay() InterRATMeasurementQuantitiesValueExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *InterRATMeasurementQuantitiesValueExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *InterRATMeasurementQuantitiesValueExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *InterRATMeasurementQuantitiesValueExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasurementQuantitiesValueExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.InterRATMeasurementQuantitiesValueExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AddOTDOACellsExtIEsExtField is ProtocolExtensionField {{Add-OTDOACells-ExtIEs}} of TS 36.455: a field carrying a value of AddOTDOACellsExtIEsValue.
type AddOTDOACellsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.AddOTDOACellsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AddOTDOACellsExtIEsExtField) WithoutReplay() AddOTDOACellsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AddOTDOACellsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AddOTDOACellsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAddOTDOACellsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAddOTDOACellsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AddOTDOACellsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AddOTDOACellsExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AddOTDOACellsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAddOTDOACellsExtIEsValueMethodReason(zero, v.Id), s02.BridgeAddOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeAddOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationFailureListExtIEsExtField is ProtocolExtensionField {{AssistanceInformationFailureList-ExtIEs}} of TS 36.455: a field carrying a value of AssistanceInformationFailureListExtIEsValue.
type AssistanceInformationFailureListExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.AssistanceInformationFailureListExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFailureListExtIEsExtField) WithoutReplay() AssistanceInformationFailureListExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationFailureListExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationFailureListExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAssistanceInformationFailureListExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AssistanceInformationFailureListExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFailureListExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AssistanceInformationFailureListExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAssistanceInformationFailureListExtIEsValueMethodReason(zero, v.Id), s02.BridgeAssistanceInformationFailureListExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeAssistanceInformationFailureListExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsIEListExtIEsExtField is ProtocolExtensionField {{CriticalityDiagnostics-IE-List-ExtIEs}} of TS 36.455: a field carrying a value of CriticalityDiagnosticsIEListExtIEsValue.
type CriticalityDiagnosticsIEListExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.CriticalityDiagnosticsIEListExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsIEListExtIEsExtField) WithoutReplay() CriticalityDiagnosticsIEListExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *CriticalityDiagnosticsIEListExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsIEListExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsIEListExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEListExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.CriticalityDiagnosticsIEListExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodReason(zero, v.Id), s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECIDMeasurementTerminationCommandMeasurementIDIEBinding binds MeasurementID to ProtocolIE-Field {{E-CIDMeasurementTerminationCommand-IEs}} of TS 36.455.
type ECIDMeasurementTerminationCommandMeasurementIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.MeasurementIDValueCodec
	inject func(s00.MeasurementID,

	) s02.ECIDMeasurementTerminationCommandIEValue

	get func(*s02.ECIDMeasurementTerminationCommandIEValue,

	) (*s00.MeasurementID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) Codec() s00.MeasurementIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) New(value s00.MeasurementID,

) (ECIDMeasurementTerminationCommandIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementTerminationCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) Get(field *ECIDMeasurementTerminationCommandIEField) (*s00.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// addOTDOACellsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.AddOTDOACellsExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.AddOTDOACellsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// assistanceInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.AssistanceInformationExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.AssistanceInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// assistanceInformationFailureListExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.AssistanceInformationFailureListExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.AssistanceInformationFailureListExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// assistanceInformationMetaDataExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.AssistanceInformationMetaDataExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.AssistanceInformationMetaDataExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// criticalityDiagnosticsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.CriticalityDiagnosticsExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.CriticalityDiagnosticsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// criticalityDiagnosticsIEListExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.CriticalityDiagnosticsIEListExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.CriticalityDiagnosticsIEListExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eCGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ECGIExtIEsValue].
type ECGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.ECGIExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.ECGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eCIDMeasurementTerminationCommandIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.ECIDMeasurementTerminationCommandIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.ECIDMeasurementTerminationCommandIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// AddOTDOACellsExtIEsIEField uses the ProtocolIE-Field shape for object set Add-OTDOACells-ExtIEs of TS 36.455.
type AddOTDOACellsExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.AddOTDOACellsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AddOTDOACellsExtIEsIEField) WithoutReplay() AddOTDOACellsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AddOTDOACellsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AddOTDOACellsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAddOTDOACellsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAddOTDOACellsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AddOTDOACellsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AddOTDOACellsExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AddOTDOACellsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAddOTDOACellsExtIEsValueMethodReason(zero, v.Id), s02.BridgeAddOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeAddOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AddOTDOACellsExtIEsIEContainer uses the ProtocolIE-Container shape for object set Add-OTDOACells-ExtIEs of TS 36.455: a list of AddOTDOACellsExtIEsIEField values.
type AddOTDOACellsExtIEsIEContainer []AddOTDOACellsExtIEsIEField

// AssistanceInformationExtIEsIEField uses the ProtocolIE-Field shape for object set Assistance-Information-ExtIEs of TS 36.455.
type AssistanceInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.AssistanceInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationExtIEsIEField) WithoutReplay() AssistanceInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAssistanceInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAssistanceInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AssistanceInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AssistanceInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAssistanceInformationExtIEsValueMethodReason(zero, v.Id), s02.BridgeAssistanceInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeAssistanceInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set Assistance-Information-ExtIEs of TS 36.455: a list of AssistanceInformationExtIEsIEField values.
type AssistanceInformationExtIEsIEContainer []AssistanceInformationExtIEsIEField

// AssistanceInformationFailureListExtIEsIEField uses the ProtocolIE-Field shape for object set AssistanceInformationFailureList-ExtIEs of TS 36.455.
type AssistanceInformationFailureListExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.AssistanceInformationFailureListExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFailureListExtIEsIEField) WithoutReplay() AssistanceInformationFailureListExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationFailureListExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationFailureListExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAssistanceInformationFailureListExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AssistanceInformationFailureListExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFailureListExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AssistanceInformationFailureListExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAssistanceInformationFailureListExtIEsValueMethodReason(zero, v.Id), s02.BridgeAssistanceInformationFailureListExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeAssistanceInformationFailureListExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationFailureListExtIEsIEContainer uses the ProtocolIE-Container shape for object set AssistanceInformationFailureList-ExtIEs of TS 36.455: a list of AssistanceInformationFailureListExtIEsIEField values.
type AssistanceInformationFailureListExtIEsIEContainer []AssistanceInformationFailureListExtIEsIEField

// AssistanceInformationMetaDataExtIEsIEField uses the ProtocolIE-Field shape for object set AssistanceInformationMetaData-ExtIEs of TS 36.455.
type AssistanceInformationMetaDataExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.AssistanceInformationMetaDataExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationMetaDataExtIEsIEField) WithoutReplay() AssistanceInformationMetaDataExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationMetaDataExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationMetaDataExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AssistanceInformationMetaDataExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationMetaDataExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.AssistanceInformationMetaDataExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodReason(zero, v.Id), s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationMetaDataExtIEsIEContainer uses the ProtocolIE-Container shape for object set AssistanceInformationMetaData-ExtIEs of TS 36.455: a list of AssistanceInformationMetaDataExtIEsIEField values.
type AssistanceInformationMetaDataExtIEsIEContainer []AssistanceInformationMetaDataExtIEsIEField

// CriticalityDiagnosticsExtIEsIEField uses the ProtocolIE-Field shape for object set CriticalityDiagnostics-ExtIEs of TS 36.455.
type CriticalityDiagnosticsExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.CriticalityDiagnosticsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsExtIEsIEField) WithoutReplay() CriticalityDiagnosticsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *CriticalityDiagnosticsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.CriticalityDiagnosticsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeCriticalityDiagnosticsExtIEsValueMethodReason(zero, v.Id), s02.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsExtIEsIEContainer uses the ProtocolIE-Container shape for object set CriticalityDiagnostics-ExtIEs of TS 36.455: a list of CriticalityDiagnosticsExtIEsIEField values.
type CriticalityDiagnosticsExtIEsIEContainer []CriticalityDiagnosticsExtIEsIEField

// CriticalityDiagnosticsIEListExtIEsIEField uses the ProtocolIE-Field shape for object set CriticalityDiagnostics-IE-List-ExtIEs of TS 36.455.
type CriticalityDiagnosticsIEListExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.CriticalityDiagnosticsIEListExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsIEListExtIEsIEField) WithoutReplay() CriticalityDiagnosticsIEListExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *CriticalityDiagnosticsIEListExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsIEListExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsIEListExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEListExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.CriticalityDiagnosticsIEListExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodReason(zero, v.Id), s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsIEListExtIEsIEContainer uses the ProtocolIE-Container shape for object set CriticalityDiagnostics-IE-List-ExtIEs of TS 36.455: a list of CriticalityDiagnosticsIEListExtIEsIEField values.
type CriticalityDiagnosticsIEListExtIEsIEContainer []CriticalityDiagnosticsIEListExtIEsIEField

// ECGIExtIEsIEField uses the ProtocolIE-Field shape for object set ECGI-ExtIEs of TS 36.455.
type ECGIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.ECGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECGIExtIEsIEField) WithoutReplay() ECGIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECGIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECGIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !s02.BridgeECGIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeECGIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ECGIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECGIExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.ECGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeECGIExtIEsValueMethodReason(zero, v.Id), s02.BridgeECGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s02.BridgeECGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECGIExtIEsIEContainer uses the ProtocolIE-Container shape for object set ECGI-ExtIEs of TS 36.455: a list of ECGIExtIEsIEField values.
type ECGIExtIEsIEContainer []ECGIExtIEsIEField

func BridgeEffectivePayloadLimits(l s00.PayloadLimits) s00.PayloadLimits {
	if l.MaxInputBytes == 0 {
		l.MaxInputBytes = 16 << 20
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = 16 << 20
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = 64
	}
	if l.MaxElements == 0 {
		l.MaxElements = 1 << 20
	}
	if l.MaxWork == 0 {
		l.MaxWork = 1 << 25
	}
	if l.MaxAllocatedBytes == 0 {
		l.MaxAllocatedBytes = 128 << 20
	}
	if l.MaxReports == 0 {
		l.MaxReports = 1024
	}
	return l
}
func BridgeInt64Ptr(v int64) *int64 { return &v }
func BridgeCaptureLPPaPosSIBsExtIEsValue(v *PosSIBsExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v PosSIBsExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v PosSIBsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v PosSIBsExtIEsValue) captureSemantics(s aper.SemanticCapture) PosSIBsExtIEsValue {
	BridgeCaptureLPPaPosSIBsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPosSIBsExtIEsValue(v *PosSIBsExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v PosSIBsExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaPosSIBsExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBsExtIEsValue) WithoutReplay() PosSIBsExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaRSSI(v *s00.RSSI, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaRepetitionNumberofSIB1NB(v *s00.RepetitionNumberofSIB1NB, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaReportCharacteristics(v *s00.ReportCharacteristics, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaResultGERANItemExtIEsValue(v *ResultGERANItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ResultGERANItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ResultGERANItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultGERANItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ResultGERANItemExtIEsValue {
	BridgeCaptureLPPaResultGERANItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultGERANItemExtIEsValue(v *ResultGERANItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultGERANItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaResultGERANItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultGERANItemExtIEsValue) WithoutReplay() ResultGERANItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultRSRPItemExtIEsValue(v *ResultRSRPItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ResultRSRPItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ResultRSRPItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultRSRPItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ResultRSRPItemExtIEsValue {
	BridgeCaptureLPPaResultRSRPItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultRSRPItemExtIEsValue(v *ResultRSRPItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultRSRPItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaResultRSRPItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRPItemExtIEsValue) WithoutReplay() ResultRSRPItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultRSRQItemExtIEsValue(v *ResultRSRQItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ResultRSRQItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ResultRSRQItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultRSRQItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ResultRSRQItemExtIEsValue {
	BridgeCaptureLPPaResultRSRQItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultRSRQItemExtIEsValue(v *ResultRSRQItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultRSRQItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaResultRSRQItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRQItemExtIEsValue) WithoutReplay() ResultRSRQItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultUTRANItemExtIEsValue(v *ResultUTRANItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ResultUTRANItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ResultUTRANItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultUTRANItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ResultUTRANItemExtIEsValue {
	BridgeCaptureLPPaResultUTRANItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultUTRANItemExtIEsValue(v *ResultUTRANItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultUTRANItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaResultUTRANItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultUTRANItemExtIEsValue) WithoutReplay() ResultUTRANItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultsPerSSBIndexItemExtIEsValue(v *ResultsPerSSBIndexItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ResultsPerSSBIndexItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ResultsPerSSBIndexItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultsPerSSBIndexItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ResultsPerSSBIndexItemExtIEsValue {
	BridgeCaptureLPPaResultsPerSSBIndexItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultsPerSSBIndexItemExtIEsValue(v *ResultsPerSSBIndexItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultsPerSSBIndexItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaResultsPerSSBIndexItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultsPerSSBIndexItemExtIEsValue) WithoutReplay() ResultsPerSSBIndexItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaSFNInitialisationTime(v *s00.SFNInitialisationTime, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCompareLPPaSSBIndex(v *s00.SSBIndex, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaSSID(v *s00.SSID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaSSNRRSRP(v *s00.SSNRRSRP, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaSSNRRSRQ(v *s00.SSNRRSRQ, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaSystemInformationExtIEsValue(v *SystemInformationExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v SystemInformationExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v SystemInformationExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v SystemInformationExtIEsValue) captureSemantics(s aper.SemanticCapture) SystemInformationExtIEsValue {
	BridgeCaptureLPPaSystemInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaSystemInformationExtIEsValue(v *SystemInformationExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v SystemInformationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaSystemInformationExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SystemInformationExtIEsValue) WithoutReplay() SystemInformationExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaTAC(v *s00.TAC, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCaptureLPPaTDDConfigurationExtIEsValue(v *TDDConfigurationExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v TDDConfigurationExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v TDDConfigurationExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v TDDConfigurationExtIEsValue) captureSemantics(s aper.SemanticCapture) TDDConfigurationExtIEsValue {
	BridgeCaptureLPPaTDDConfigurationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaTDDConfigurationExtIEsValue(v *TDDConfigurationExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v TDDConfigurationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaTDDConfigurationExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TDDConfigurationExtIEsValue) WithoutReplay() TDDConfigurationExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaTPID(v *s00.TPID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaTPType(v *s00.TPType, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaTriggeringMessage(v *s00.TriggeringMessage, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaTypeOfError(v *s00.TypeOfError, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaUARFCN(v *s00.UARFCN, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaUTRAEcN0(v *s00.UTRAEcN0, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaUTRARSCP(v *s00.UTRARSCP, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaValueRSRP(v *s00.ValueRSRP, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaValueRSRQ(v *s00.ValueRSRQ, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaWLANBand(v *s00.WLANBand, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANChannel(v *s00.WLANChannel, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANChannelList(v *s00.WLANChannelList, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaWLANChannel(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareLPPaWLANCountryCode(v *s00.WLANCountryCode, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANMeasurementQuantitiesValue(v *s00.WLANMeasurementQuantitiesValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesValueExtIEsValue(v *WLANMeasurementQuantitiesValueExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v WLANMeasurementQuantitiesValueExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) captureSemantics(s aper.SemanticCapture) WLANMeasurementQuantitiesValueExtIEsValue {
	BridgeCaptureLPPaWLANMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaWLANMeasurementQuantitiesValueExtIEsValue(v *WLANMeasurementQuantitiesValueExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaWLANMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesValueExtIEsValue) WithoutReplay() WLANMeasurementQuantitiesValueExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaWLANMeasurementResultItemExtIEsValue(v *WLANMeasurementResultItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v WLANMeasurementResultItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v WLANMeasurementResultItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v WLANMeasurementResultItemExtIEsValue) captureSemantics(s aper.SemanticCapture) WLANMeasurementResultItemExtIEsValue {
	BridgeCaptureLPPaWLANMeasurementResultItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaWLANMeasurementResultItemExtIEsValue(v *WLANMeasurementResultItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v WLANMeasurementResultItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaWLANMeasurementResultItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementResultItemExtIEsValue) WithoutReplay() WLANMeasurementResultItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaWLANOperatingClass(v *s00.WLANOperatingClass, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANRSSI(v *s00.WLANRSSI, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}

type PosSIBsExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v PosSIBsExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *PosSIBsExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (PosSIBsExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIBs-ExtIEs"}}
}
func (PosSIBsExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v PosSIBsExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PosSIBsExtIEsValue, error) {
	out := PosSIBsExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v PosSIBsExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PosSIBsExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PosSIBsExtIEsValue:", v.id)
	}
}

type ResultGERANItemExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v ResultGERANItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ResultGERANItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultGERANItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultGERAN-Item-ExtIEs"}}
}
func (ResultGERANItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v ResultGERANItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResultGERANItemExtIEsValue, error) {
	out := ResultGERANItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v ResultGERANItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultGERANItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResultGERANItemExtIEsValue:", v.id)
	}
}

type ResultRSRPItemExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v ResultRSRPItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ResultRSRPItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultRSRPItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRP-Item-ExtIEs"}}
}
func (ResultRSRPItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v ResultRSRPItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResultRSRPItemExtIEsValue, error) {
	out := ResultRSRPItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v ResultRSRPItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultRSRPItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResultRSRPItemExtIEsValue:", v.id)
	}
}

type ResultRSRQItemExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v ResultRSRQItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ResultRSRQItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultRSRQItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRQ-Item-ExtIEs"}}
}
func (ResultRSRQItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v ResultRSRQItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResultRSRQItemExtIEsValue, error) {
	out := ResultRSRQItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v ResultRSRQItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultRSRQItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResultRSRQItemExtIEsValue:", v.id)
	}
}

type ResultUTRANItemExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v ResultUTRANItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ResultUTRANItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultUTRANItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultUTRAN-Item-ExtIEs"}}
}
func (ResultUTRANItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v ResultUTRANItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResultUTRANItemExtIEsValue, error) {
	out := ResultUTRANItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v ResultUTRANItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultUTRANItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResultUTRANItemExtIEsValue:", v.id)
	}
}

type ResultsPerSSBIndexItemExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v ResultsPerSSBIndexItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ResultsPerSSBIndexItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultsPerSSBIndexItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultsPerSSB-Index-Item-ExtIEs"}}
}
func (ResultsPerSSBIndexItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v ResultsPerSSBIndexItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResultsPerSSBIndexItemExtIEsValue, error) {
	out := ResultsPerSSBIndexItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v ResultsPerSSBIndexItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultsPerSSBIndexItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResultsPerSSBIndexItemExtIEsValue:", v.id)
	}
}

type SystemInformationExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v SystemInformationExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *SystemInformationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (SystemInformationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "SystemInformation-ExtIEs"}}
}
func (SystemInformationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v SystemInformationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SystemInformationExtIEsValue, error) {
	out := SystemInformationExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v SystemInformationExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v SystemInformationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SystemInformationExtIEsValue:", v.id)
	}
}

type TDDConfigurationExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v TDDConfigurationExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *TDDConfigurationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (TDDConfigurationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "TDDConfiguration-ExtIEs"}}
}
func (TDDConfigurationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v TDDConfigurationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (TDDConfigurationExtIEsValue, error) {
	out := TDDConfigurationExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v TDDConfigurationExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v TDDConfigurationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "TDDConfigurationExtIEsValue:", v.id)
	}
}

type WLANMeasurementQuantitiesValueExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v WLANMeasurementQuantitiesValueExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *WLANMeasurementQuantitiesValueExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (WLANMeasurementQuantitiesValueExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantitiesValue-ExtIEs"}}
}
func (WLANMeasurementQuantitiesValueExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (WLANMeasurementQuantitiesValueExtIEsValue, error) {
	out := WLANMeasurementQuantitiesValueExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "WLANMeasurementQuantitiesValueExtIEsValue:", v.id)
	}
}

type WLANMeasurementResultItemExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v WLANMeasurementResultItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *WLANMeasurementResultItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (WLANMeasurementResultItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementResult-Item-ExtIEs"}}
}
func (WLANMeasurementResultItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v WLANMeasurementResultItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (WLANMeasurementResultItemExtIEsValue, error) {
	out := WLANMeasurementResultItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v WLANMeasurementResultItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v WLANMeasurementResultItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "WLANMeasurementResultItemExtIEsValue:", v.id)
	}
}

type AddOTDOACellsExtIETable struct{}

func AddOTDOACellsExtIEs() AddOTDOACellsExtIETable { return AddOTDOACellsExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (AddOTDOACellsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Add-OTDOACells-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t AddOTDOACellsExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (AddOTDOACellsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AddOTDOACellsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AddOTDOACellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AddOTDOACellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AddOTDOACellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AddOTDOACellsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.AddOTDOACellsExtIEsValue {
			sealed := s02.AddOTDOACellsExtIEsValue{}
			*s02.BridgeAddOTDOACellsExtIEsValueFieldId(&sealed) = id
			*s02.BridgeAddOTDOACellsExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeAddOTDOACellsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type AssistanceInformationExtIETable struct{}

func AssistanceInformationExtIEs() AssistanceInformationExtIETable {
	return AssistanceInformationExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (AssistanceInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Assistance-Information-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t AssistanceInformationExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (AssistanceInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AssistanceInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AssistanceInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.AssistanceInformationExtIEsValue {
			sealed := s02.AssistanceInformationExtIEsValue{}
			*s02.BridgeAssistanceInformationExtIEsValueFieldId(&sealed) = id
			*s02.BridgeAssistanceInformationExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeAssistanceInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type AssistanceInformationFailureListExtIETable struct{}

func AssistanceInformationFailureListExtIEs() AssistanceInformationFailureListExtIETable {
	return AssistanceInformationFailureListExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (AssistanceInformationFailureListExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationFailureList-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t AssistanceInformationFailureListExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (AssistanceInformationFailureListExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationFailureListExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AssistanceInformationFailureListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationFailureListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationFailureListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AssistanceInformationFailureListExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.AssistanceInformationFailureListExtIEsValue {
			sealed := s02.AssistanceInformationFailureListExtIEsValue{}
			*s02.BridgeAssistanceInformationFailureListExtIEsValueFieldId(&sealed) = id
			*s02.BridgeAssistanceInformationFailureListExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeAssistanceInformationFailureListExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type AssistanceInformationMetaDataExtIETable struct{}

func AssistanceInformationMetaDataExtIEs() AssistanceInformationMetaDataExtIETable {
	return AssistanceInformationMetaDataExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (AssistanceInformationMetaDataExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationMetaData-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t AssistanceInformationMetaDataExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (AssistanceInformationMetaDataExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationMetaDataExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AssistanceInformationMetaDataExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationMetaDataExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationMetaDataExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AssistanceInformationMetaDataExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.AssistanceInformationMetaDataExtIEsValue {
			sealed := s02.AssistanceInformationMetaDataExtIEsValue{}
			*s02.BridgeAssistanceInformationMetaDataExtIEsValueFieldId(&sealed) = id
			*s02.BridgeAssistanceInformationMetaDataExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeAssistanceInformationMetaDataExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CriticalityDiagnosticsExtIETable struct{}

func CriticalityDiagnosticsExtIEs() CriticalityDiagnosticsExtIETable {
	return CriticalityDiagnosticsExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (CriticalityDiagnosticsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t CriticalityDiagnosticsExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (CriticalityDiagnosticsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CriticalityDiagnosticsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CriticalityDiagnosticsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.CriticalityDiagnosticsExtIEsValue {
			sealed := s02.CriticalityDiagnosticsExtIEsValue{}
			*s02.BridgeCriticalityDiagnosticsExtIEsValueFieldId(&sealed) = id
			*s02.BridgeCriticalityDiagnosticsExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeCriticalityDiagnosticsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CriticalityDiagnosticsIEListExtIETable struct{}

func CriticalityDiagnosticsIEListExtIEs() CriticalityDiagnosticsIEListExtIETable {
	return CriticalityDiagnosticsIEListExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (CriticalityDiagnosticsIEListExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-IE-List-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t CriticalityDiagnosticsIEListExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (CriticalityDiagnosticsIEListExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CriticalityDiagnosticsIEListExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CriticalityDiagnosticsIEListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CriticalityDiagnosticsIEListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return CriticalityDiagnosticsIEListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CriticalityDiagnosticsIEListExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.CriticalityDiagnosticsIEListExtIEsValue {
			sealed := s02.CriticalityDiagnosticsIEListExtIEsValue{}
			*s02.BridgeCriticalityDiagnosticsIEListExtIEsValueFieldId(&sealed) = id
			*s02.BridgeCriticalityDiagnosticsIEListExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeCriticalityDiagnosticsIEListExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ECGIExtIETable struct{}

func ECGIExtIEs() ECGIExtIETable { return ECGIExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ECGIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECGI-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ECGIExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ECGIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECGIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ECGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ECGIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.ECGIExtIEsValue {
			sealed := s02.ECGIExtIEsValue{}
			*s02.BridgeECGIExtIEsValueFieldId(&sealed) = id
			*s02.BridgeECGIExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeECGIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type InterRATMeasurementQuantitiesValueExtIETable struct{}

func InterRATMeasurementQuantitiesValueExtIEs() InterRATMeasurementQuantitiesValueExtIETable {
	return InterRATMeasurementQuantitiesValueExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (InterRATMeasurementQuantitiesValueExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantitiesValue-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t InterRATMeasurementQuantitiesValueExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (InterRATMeasurementQuantitiesValueExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InterRATMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InterRATMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InterRATMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return InterRATMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return InterRATMeasurementQuantitiesValueExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.InterRATMeasurementQuantitiesValueExtIEsValue {
			sealed := s02.InterRATMeasurementQuantitiesValueExtIEsValue{}
			*s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldId(&sealed) = id
			*s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ECIDMeasurementTerminationCommandIETable struct{}

func ECIDMeasurementTerminationCommandIEs() ECIDMeasurementTerminationCommandIETable {
	return ECIDMeasurementTerminationCommandIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (ECIDMeasurementTerminationCommandIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementTerminationCommandIETable) infoESMLCUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementTerminationCommandIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}

// ESMLCUEMeasurementID returns the typed binding for the ESMLCUEMeasurementID row of this table.
func (t ECIDMeasurementTerminationCommandIETable) ESMLCUEMeasurementID() ECIDMeasurementTerminationCommandMeasurementIDIEBinding {
	return ECIDMeasurementTerminationCommandMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero s02.ECIDMeasurementTerminationCommandIEValue
			decoded, err := s02.BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(zero, s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementTerminationCommand-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s02.BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh((func() s02.ECIDMeasurementTerminationCommandIEValue {
				sealed := s02.ECIDMeasurementTerminationCommandIEValue{}
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s00.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v s00.MeasurementID, options aper.DecodeState) (s00.MeasurementID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v s00.MeasurementID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MeasurementID) s02.ECIDMeasurementTerminationCommandIEValue {
			return func() s02.ECIDMeasurementTerminationCommandIEValue {
				sealed := s02.ECIDMeasurementTerminationCommandIEValue{}
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s02.ECIDMeasurementTerminationCommandIEValue) (*s00.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementTerminationCommandIETable) infoENBUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementTerminationCommandIEs().ID(), ID: s00.ProtocolIEID(6), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}

// ENBUEMeasurementID returns the typed binding for the ENBUEMeasurementID row of this table.
func (t ECIDMeasurementTerminationCommandIETable) ENBUEMeasurementID() ECIDMeasurementTerminationCommandMeasurementIDIEBinding {
	return ECIDMeasurementTerminationCommandMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero s02.ECIDMeasurementTerminationCommandIEValue
			decoded, err := s02.BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(zero, s00.ProtocolIEID(6), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementTerminationCommand-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s02.BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh((func() s02.ECIDMeasurementTerminationCommandIEValue {
				sealed := s02.ECIDMeasurementTerminationCommandIEValue{}
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(6)
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldRowENBUEMeasurementID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s00.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v s00.MeasurementID, options aper.DecodeState) (s00.MeasurementID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v s00.MeasurementID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MeasurementID) s02.ECIDMeasurementTerminationCommandIEValue {
			return func() s02.ECIDMeasurementTerminationCommandIEValue {
				sealed := s02.ECIDMeasurementTerminationCommandIEValue{}
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(6)
				*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldRowENBUEMeasurementID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s02.ECIDMeasurementTerminationCommandIEValue) (*s00.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ECIDMeasurementTerminationCommandIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ECIDMeasurementTerminationCommandIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(6):
		return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementTerminationCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		return ECIDMeasurementTerminationCommandIEField{Id: id, Criticality: criticality, Value: func() s02.ECIDMeasurementTerminationCommandIEValue {
			sealed := s02.ECIDMeasurementTerminationCommandIEValue{}
			*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = id
			*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldOpaque(&sealed) = retained
			*s02.BridgeECIDMeasurementTerminationCommandIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// RSSICodec binds the complete source value type.
func RSSICodec() s01.RSSIValueCodec {
	return func() s01.RSSIValueCodec {
		sealed := s01.RSSIValueCodec{}
		*s01.BridgeRSSIValueCodecFieldPath(&sealed) = "RSSI"
		*s01.BridgeRSSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RSSI, error) {
			var zero s00.RSSI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "RSSI"); err != nil {
				return zero, err
			}
			return s00.RSSI(decoded), nil
		}
		*s01.BridgeRSSIValueCodecFieldEncode(&sealed) = func(value s00.RSSI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeRSSIValueCodecFieldCapture(&sealed) = func(v s00.RSSI, options aper.DecodeState) (s00.RSSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaRSSI(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRSSIValueCodecFieldCompare(&sealed) = func(v s00.RSSI, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaRSSI(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*s01.BridgeRSSIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RSSI"
			return sealed
		}()
		return sealed
	}()

}

// RepetitionNumberofSIB1NBCodec binds the complete source value type.
func RepetitionNumberofSIB1NBCodec() s01.RepetitionNumberofSIB1NBValueCodec {
	return func() s01.RepetitionNumberofSIB1NBValueCodec {
		sealed := s01.RepetitionNumberofSIB1NBValueCodec{}
		*s01.BridgeRepetitionNumberofSIB1NBValueCodecFieldPath(&sealed) = "RepetitionNumberofSIB1NB"
		*s01.BridgeRepetitionNumberofSIB1NBValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RepetitionNumberofSIB1NB, error) {
			var zero s00.RepetitionNumberofSIB1NB
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "RepetitionNumberofSIB1NB"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "RepetitionNumberofSIB1NB"); err != nil {
				return zero, err
			}
			return s00.RepetitionNumberofSIB1NB(decoded), nil
		}
		*s01.BridgeRepetitionNumberofSIB1NBValueCodecFieldEncode(&sealed) = func(value s00.RepetitionNumberofSIB1NB, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeRepetitionNumberofSIB1NBValueCodecFieldCapture(&sealed) = func(v s00.RepetitionNumberofSIB1NB, options aper.DecodeState) (s00.RepetitionNumberofSIB1NB, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaRepetitionNumberofSIB1NB(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRepetitionNumberofSIB1NBValueCodecFieldCompare(&sealed) = func(v s00.RepetitionNumberofSIB1NB, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaRepetitionNumberofSIB1NB(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*s01.BridgeRepetitionNumberofSIB1NBValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RepetitionNumberofSIB1NB"
			return sealed
		}()
		return sealed
	}()

}

// SFNInitialisationTimeCodec binds the complete source value type.
func SFNInitialisationTimeCodec() s01.SFNInitialisationTimeValueCodec {
	return func() s01.SFNInitialisationTimeValueCodec {
		sealed := s01.SFNInitialisationTimeValueCodec{}
		*s01.BridgeSFNInitialisationTimeValueCodecFieldPath(&sealed) = "SFNInitialisationTime"
		*s01.BridgeSFNInitialisationTimeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SFNInitialisationTime, error) {
			var zero s00.SFNInitialisationTime
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			bits, length, err := aper.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SFNInitialisationTime"); err != nil {
				return zero, err
			}
			return s00.SFNInitialisationTime(runtime.BitString{Bytes: bits, BitLength: length}), nil
		}
		*s01.BridgeSFNInitialisationTimeValueCodecFieldEncode(&sealed) = func(value s00.SFNInitialisationTime, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeBitStringAligned(bb, value.Bytes, value.BitLength, 64, 64, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeSFNInitialisationTimeValueCodecFieldCapture(&sealed) = func(v s00.SFNInitialisationTime, options aper.DecodeState) (s00.SFNInitialisationTime, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaSFNInitialisationTime(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeSFNInitialisationTimeValueCodecFieldCompare(&sealed) = func(v s00.SFNInitialisationTime, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaSFNInitialisationTime(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeSFNInitialisationTimeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SFNInitialisationTime"
			return sealed
		}()
		return sealed
	}()

}

// SSIDCodec binds the complete source value type.
func SSIDCodec() s01.SSIDValueCodec {
	return func() s01.SSIDValueCodec {
		sealed := s01.SSIDValueCodec{}
		*s01.BridgeSSIDValueCodecFieldPath(&sealed) = "SSID"
		*s01.BridgeSSIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SSID, error) {
			var zero s00.SSID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := aper.DecodeOctetStringAligned(bb, 1, 32, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SSID"); err != nil {
				return zero, err
			}
			return s00.SSID(octets), nil
		}
		*s01.BridgeSSIDValueCodecFieldEncode(&sealed) = func(value s00.SSID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeOctetStringAligned(bb, []byte(value), 1, 32, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeSSIDValueCodecFieldCapture(&sealed) = func(v s00.SSID, options aper.DecodeState) (s00.SSID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaSSID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSSIDValueCodecFieldCompare(&sealed) = func(v s00.SSID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaSSID(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*s01.BridgeSSIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SSID"
			return sealed
		}()
		return sealed
	}()

}

// TACCodec binds the complete source value type.
func TACCodec() s01.TACValueCodec {
	return func() s01.TACValueCodec {
		sealed := s01.TACValueCodec{}
		*s01.BridgeTACValueCodecFieldPath(&sealed) = "TAC"
		*s01.BridgeTACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TAC, error) {
			var zero s00.TAC
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TAC"); err != nil {
				return zero, err
			}
			return s00.TAC(octets), nil
		}
		*s01.BridgeTACValueCodecFieldEncode(&sealed) = func(value s00.TAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeOctetStringAligned(bb, []byte(value), 2, 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeTACValueCodecFieldCapture(&sealed) = func(v s00.TAC, options aper.DecodeState) (s00.TAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaTAC(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTACValueCodecFieldCompare(&sealed) = func(v s00.TAC, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaTAC(&v, &s)
			s.End(f, root,
				false)
			return s.Plan()
		}
		*s01.BridgeTACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAC"
			return sealed
		}()
		return sealed
	}()

}

// TPIDCodec binds the complete source value type.
func TPIDCodec() s01.TPIDValueCodec {
	return func() s01.TPIDValueCodec {
		sealed := s01.TPIDValueCodec{}
		*s01.BridgeTPIDValueCodecFieldPath(&sealed) = "TPID"
		*s01.BridgeTPIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TPID, error) {
			var zero s00.TPID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TPID"); err != nil {
				return zero, err
			}
			return s00.TPID(decoded), nil
		}
		*s01.BridgeTPIDValueCodecFieldEncode(&sealed) = func(value s00.TPID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeTPIDValueCodecFieldCapture(&sealed) = func(v s00.TPID, options aper.DecodeState) (s00.TPID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaTPID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTPIDValueCodecFieldCompare(&sealed) = func(v s00.TPID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaTPID(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*s01.BridgeTPIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TPID"
			return sealed
		}()
		return sealed
	}()

}

// TPTypeCodec binds the complete source value type.
func TPTypeCodec() s01.TPTypeValueCodec {
	return func() s01.TPTypeValueCodec {
		sealed := s01.TPTypeValueCodec{}
		*s01.BridgeTPTypeValueCodecFieldPath(&sealed) = "TPType"
		*s01.BridgeTPTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TPType, error) {
			var zero s00.TPType
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TPType"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TPType"); err != nil {
				return zero, err
			}
			return s00.TPType(decoded), nil
		}
		*s01.BridgeTPTypeValueCodecFieldEncode(&sealed) = func(value s00.TPType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeTPTypeValueCodecFieldCapture(&sealed) = func(v s00.TPType, options aper.DecodeState) (s00.TPType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaTPType(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTPTypeValueCodecFieldCompare(&sealed) = func(v s00.TPType, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaTPType(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeTPTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TPType"
			return sealed
		}()
		return sealed
	}()

}

// TriggeringMessageCodec binds the complete source value type.
func TriggeringMessageCodec() s01.TriggeringMessageValueCodec {
	return func() s01.TriggeringMessageValueCodec {
		sealed := s01.TriggeringMessageValueCodec{}
		*s01.BridgeTriggeringMessageValueCodecFieldPath(&sealed) = "TriggeringMessage"
		*s01.BridgeTriggeringMessageValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TriggeringMessage, error) {
			var zero s00.TriggeringMessage
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "TriggeringMessage"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TriggeringMessage"); err != nil {
				return zero, err
			}
			return s00.TriggeringMessage(decoded), nil
		}
		*s01.BridgeTriggeringMessageValueCodecFieldEncode(&sealed) = func(value s00.TriggeringMessage, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 3, false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeTriggeringMessageValueCodecFieldCapture(&sealed) = func(v s00.TriggeringMessage, options aper.DecodeState) (s00.TriggeringMessage, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaTriggeringMessage(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgeTriggeringMessageValueCodecFieldCompare(&sealed) = func(v s00.TriggeringMessage, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaTriggeringMessage(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeTriggeringMessageValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TriggeringMessage"
			return sealed
		}()
		return sealed
	}()

}

// TypeOfErrorCodec binds the complete source value type.
func TypeOfErrorCodec() s01.TypeOfErrorValueCodec {
	return func() s01.TypeOfErrorValueCodec {
		sealed := s01.TypeOfErrorValueCodec{}
		*s01.BridgeTypeOfErrorValueCodecFieldPath(&sealed) = "TypeOfError"
		*s01.BridgeTypeOfErrorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TypeOfError, error) {
			var zero s00.TypeOfError
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TypeOfError"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TypeOfError"); err != nil {
				return zero, err
			}
			return s00.TypeOfError(decoded), nil
		}
		*s01.BridgeTypeOfErrorValueCodecFieldEncode(&sealed) = func(value s00.TypeOfError, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeTypeOfErrorValueCodecFieldCapture(&sealed) = func(v s00.TypeOfError, options aper.DecodeState) (s00.TypeOfError, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaTypeOfError(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*s01.BridgeTypeOfErrorValueCodecFieldCompare(&sealed) = func(v s00.TypeOfError, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaTypeOfError(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeTypeOfErrorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TypeOfError"
			return sealed
		}()
		return sealed
	}()

}

// UARFCNCodec binds the complete source value type.
func UARFCNCodec() s01.UARFCNValueCodec {
	return func() s01.UARFCNValueCodec {
		sealed := s01.UARFCNValueCodec{}
		*s01.BridgeUARFCNValueCodecFieldPath(&sealed) = "UARFCN"
		*s01.BridgeUARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UARFCN, error) {
			var zero s00.UARFCN
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound10, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "UARFCN"); err != nil {
				return zero, err
			}
			return s00.UARFCN(decoded), nil
		}
		*s01.BridgeUARFCNValueCodecFieldEncode(&sealed) = func(value s00.UARFCN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound10, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeUARFCNValueCodecFieldCapture(&sealed) = func(v s00.UARFCN, options aper.DecodeState) (s00.UARFCN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaUARFCN(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeUARFCNValueCodecFieldCompare(&sealed) = func(v s00.UARFCN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaUARFCN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeUARFCNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UARFCN"
			return sealed
		}()
		return sealed
	}()

}

// UTRAEcN0Codec binds the complete source value type.
func UTRAEcN0Codec() s01.UTRAEcN0ValueCodec {
	return func() s01.UTRAEcN0ValueCodec {
		sealed := s01.UTRAEcN0ValueCodec{}
		*s01.BridgeUTRAEcN0ValueCodecFieldPath(&sealed) = "UTRAEcN0"
		*s01.BridgeUTRAEcN0ValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UTRAEcN0, error) {
			var zero s00.UTRAEcN0
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound15, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "UTRAEcN0"); err != nil {
				return zero, err
			}
			return s00.UTRAEcN0(decoded), nil
		}
		*s01.BridgeUTRAEcN0ValueCodecFieldEncode(&sealed) = func(value s00.UTRAEcN0, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound15, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeUTRAEcN0ValueCodecFieldCapture(&sealed) = func(v s00.UTRAEcN0, options aper.DecodeState) (s00.UTRAEcN0, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaUTRAEcN0(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeUTRAEcN0ValueCodecFieldCompare(&sealed) = func(v s00.UTRAEcN0, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaUTRAEcN0(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeUTRAEcN0ValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UTRAEcN0"
			return sealed
		}()
		return sealed
	}()

}

// UTRARSCPCodec binds the complete source value type.
func UTRARSCPCodec() s01.UTRARSCPValueCodec {
	return func() s01.UTRARSCPValueCodec {
		sealed := s01.UTRARSCPValueCodec{}
		*s01.BridgeUTRARSCPValueCodecFieldPath(&sealed) = "UTRARSCP"
		*s01.BridgeUTRARSCPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UTRARSCP, error) {
			var zero s00.UTRARSCP
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound21, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "UTRARSCP"); err != nil {
				return zero, err
			}
			return s00.UTRARSCP(decoded), nil
		}
		*s01.BridgeUTRARSCPValueCodecFieldEncode(&sealed) = func(value s00.UTRARSCP, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound21, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeUTRARSCPValueCodecFieldCapture(&sealed) = func(v s00.UTRARSCP, options aper.DecodeState) (s00.UTRARSCP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaUTRARSCP(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeUTRARSCPValueCodecFieldCompare(&sealed) = func(v s00.UTRARSCP, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaUTRARSCP(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeUTRARSCPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UTRARSCP"
			return sealed
		}()
		return sealed
	}()

}

// ValueRSRPCodec binds the complete source value type.
func ValueRSRPCodec() s01.ValueRSRPValueCodec {
	return func() s01.ValueRSRPValueCodec {
		sealed := s01.ValueRSRPValueCodec{}
		*s01.BridgeValueRSRPValueCodecFieldPath(&sealed) = "ValueRSRP"
		*s01.BridgeValueRSRPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ValueRSRP, error) {
			var zero s00.ValueRSRP
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound22, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ValueRSRP"); err != nil {
				return zero, err
			}
			return s00.ValueRSRP(decoded), nil
		}
		*s01.BridgeValueRSRPValueCodecFieldEncode(&sealed) = func(value s00.ValueRSRP, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound22, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeValueRSRPValueCodecFieldCapture(&sealed) = func(v s00.ValueRSRP, options aper.DecodeState) (s00.ValueRSRP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaValueRSRP(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeValueRSRPValueCodecFieldCompare(&sealed) = func(v s00.ValueRSRP, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaValueRSRP(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeValueRSRPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ValueRSRP"
			return sealed
		}()
		return sealed
	}()

}

// ValueRSRQCodec binds the complete source value type.
func ValueRSRQCodec() s01.ValueRSRQValueCodec {
	return func() s01.ValueRSRQValueCodec {
		sealed := s01.ValueRSRQValueCodec{}
		*s01.BridgeValueRSRQValueCodecFieldPath(&sealed) = "ValueRSRQ"
		*s01.BridgeValueRSRQValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ValueRSRQ, error) {
			var zero s00.ValueRSRQ
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ValueRSRQ"); err != nil {
				return zero, err
			}
			return s00.ValueRSRQ(decoded), nil
		}
		*s01.BridgeValueRSRQValueCodecFieldEncode(&sealed) = func(value s00.ValueRSRQ, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeValueRSRQValueCodecFieldCapture(&sealed) = func(v s00.ValueRSRQ, options aper.DecodeState) (s00.ValueRSRQ, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaValueRSRQ(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeValueRSRQValueCodecFieldCompare(&sealed) = func(v s00.ValueRSRQ, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaValueRSRQ(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeValueRSRQValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ValueRSRQ"
			return sealed
		}()
		return sealed
	}()

}

// WLANBandCodec binds the complete source value type.
func WLANBandCodec() s01.WLANBandValueCodec {
	return func() s01.WLANBandValueCodec {
		sealed := s01.WLANBandValueCodec{}
		*s01.BridgeWLANBandValueCodecFieldPath(&sealed) = "WLANBand"
		*s01.BridgeWLANBandValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANBand, error) {
			var zero s00.WLANBand
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WLANBand"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANBand"); err != nil {
				return zero, err
			}
			return s00.WLANBand(decoded), nil
		}
		*s01.BridgeWLANBandValueCodecFieldEncode(&sealed) = func(value s00.WLANBand, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeWLANBandValueCodecFieldCapture(&sealed) = func(v s00.WLANBand, options aper.DecodeState) (s00.WLANBand, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaWLANBand(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeWLANBandValueCodecFieldCompare(&sealed) = func(v s00.WLANBand, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANBand(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeWLANBandValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANBand"
			return sealed
		}()
		return sealed
	}()

}

// WLANCountryCodeCodec binds the complete source value type.
func WLANCountryCodeCodec() s02.WLANCountryCodeValueCodec {
	return func() s02.WLANCountryCodeValueCodec {
		sealed := s02.WLANCountryCodeValueCodec{}
		*s02.BridgeWLANCountryCodeValueCodecFieldPath(&sealed) = "WLANCountryCode"
		*s02.BridgeWLANCountryCodeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANCountryCode, error) {
			var zero s00.WLANCountryCode
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WLANCountryCode"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANCountryCode"); err != nil {
				return zero, err
			}
			return s00.WLANCountryCode(decoded), nil
		}
		*s02.BridgeWLANCountryCodeValueCodecFieldEncode(&sealed) = func(value s00.WLANCountryCode, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 4, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s02.BridgeWLANCountryCodeValueCodecFieldCapture(&sealed) = func(v s00.WLANCountryCode, options aper.DecodeState) (s00.WLANCountryCode, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaWLANCountryCode(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWLANCountryCodeValueCodecFieldCompare(&sealed) = func(v s00.WLANCountryCode, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANCountryCode(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s02.BridgeWLANCountryCodeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANCountryCode"
			return sealed
		}()
		return sealed
	}()

}

// WLANMeasurementQuantitiesValueCodec binds the complete source value type.
func WLANMeasurementQuantitiesValueCodec() s02.WLANMeasurementQuantitiesValueValueCodec {
	return func() s02.WLANMeasurementQuantitiesValueValueCodec {
		sealed := s02.WLANMeasurementQuantitiesValueValueCodec{}
		*s02.BridgeWLANMeasurementQuantitiesValueValueCodecFieldPath(&sealed) = "WLANMeasurementQuantitiesValue"
		*s02.BridgeWLANMeasurementQuantitiesValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANMeasurementQuantitiesValue, error) {
			var zero s00.WLANMeasurementQuantitiesValue
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WLANMeasurementQuantitiesValue"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANMeasurementQuantitiesValue"); err != nil {
				return zero, err
			}
			return s00.WLANMeasurementQuantitiesValue(decoded), nil
		}
		*s02.BridgeWLANMeasurementQuantitiesValueValueCodecFieldEncode(&sealed) = func(value s00.WLANMeasurementQuantitiesValue, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s02.BridgeWLANMeasurementQuantitiesValueValueCodecFieldCapture(&sealed) = func(v s00.WLANMeasurementQuantitiesValue, options aper.DecodeState) (s00.WLANMeasurementQuantitiesValue, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaWLANMeasurementQuantitiesValue(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWLANMeasurementQuantitiesValueValueCodecFieldCompare(&sealed) = func(v s00.WLANMeasurementQuantitiesValue, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANMeasurementQuantitiesValue(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s02.BridgeWLANMeasurementQuantitiesValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementQuantitiesValue"
			return sealed
		}()
		return sealed
	}()

}

// WLANRSSICodec binds the complete source value type.
func WLANRSSICodec() s02.WLANRSSIValueCodec {
	return func() s02.WLANRSSIValueCodec {
		sealed := s02.WLANRSSIValueCodec{}
		*s02.BridgeWLANRSSIValueCodecFieldPath(&sealed) = "WLANRSSI"
		*s02.BridgeWLANRSSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANRSSI, error) {
			var zero s00.WLANRSSI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANRSSI"); err != nil {
				return zero, err
			}
			return s00.WLANRSSI(decoded), nil
		}
		*s02.BridgeWLANRSSIValueCodecFieldEncode(&sealed) = func(value s00.WLANRSSI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s02.BridgeWLANRSSIValueCodecFieldCapture(&sealed) = func(v s00.WLANRSSI, options aper.DecodeState) (s00.WLANRSSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaWLANRSSI(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWLANRSSIValueCodecFieldCompare(&sealed) = func(v s00.WLANRSSI, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANRSSI(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s02.BridgeWLANRSSIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANRSSI"
			return sealed
		}()
		return sealed
	}()

}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *PosSIBsExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResultGERANItemExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResultRSRPItemExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResultRSRQItemExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResultUTRANItemExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResultsPerSSBIndexItemExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SystemInformationExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *TDDConfigurationExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *WLANMeasurementQuantitiesValueExtIEsValue) Selected() (any, bool) { return nil, false }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *WLANMeasurementResultItemExtIEsValue) Selected() (any, bool) { return nil, false }

func BridgeAddOTDOACellsExtIEsExtFieldFieldReceived(v *AddOTDOACellsExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeAddOTDOACellsExtIEsExtFieldFieldReplay(v *AddOTDOACellsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsExtIEsExtFieldFieldStream(v *AddOTDOACellsExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeAddOTDOACellsExtIEsExtFieldFieldWithoutReplay(v *AddOTDOACellsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(v *AddOTDOACellsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAddOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(v *AddOTDOACellsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldReceived(v *AddOTDOACellsExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldReplay(v *AddOTDOACellsExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldStream(v *AddOTDOACellsExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldWithoutReplay(v *AddOTDOACellsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsExtIEsIEFieldMethodMarshalAPERTo(v *AddOTDOACellsExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAddOTDOACellsExtIEsIEFieldMethodUnmarshalAPERFrom(v *AddOTDOACellsExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationExtIEsExtFieldFieldReceived(v *AssistanceInformationExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationExtIEsExtFieldFieldReplay(v *AssistanceInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationExtIEsExtFieldFieldStream(v *AssistanceInformationExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v *AssistanceInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationExtIEsIEFieldFieldReceived(v *AssistanceInformationExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationExtIEsIEFieldFieldReplay(v *AssistanceInformationExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationExtIEsIEFieldFieldStream(v *AssistanceInformationExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationExtIEsIEFieldFieldWithoutReplay(v *AssistanceInformationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationExtIEsIEFieldMethodMarshalAPERTo(v *AssistanceInformationExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationExtIEsIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReceived(v *AssistanceInformationFailureListExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReplay(v *AssistanceInformationFailureListExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldStream(v *AssistanceInformationFailureListExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldWithoutReplay(v *AssistanceInformationFailureListExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceInformationFailureListExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceInformationFailureListExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldReceived(v *AssistanceInformationFailureListExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldReplay(v *AssistanceInformationFailureListExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldStream(v *AssistanceInformationFailureListExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldWithoutReplay(v *AssistanceInformationFailureListExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldMethodMarshalAPERTo(v *AssistanceInformationFailureListExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationFailureListExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReceived(v *AssistanceInformationMetaDataExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReplay(v *AssistanceInformationMetaDataExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldStream(v *AssistanceInformationMetaDataExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldWithoutReplay(v *AssistanceInformationMetaDataExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceInformationMetaDataExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceInformationMetaDataExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldReceived(v *AssistanceInformationMetaDataExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldReplay(v *AssistanceInformationMetaDataExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldStream(v *AssistanceInformationMetaDataExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldWithoutReplay(v *AssistanceInformationMetaDataExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldMethodMarshalAPERTo(v *AssistanceInformationMetaDataExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationMetaDataExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReceived(v *CriticalityDiagnosticsExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v *CriticalityDiagnosticsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldStream(v *CriticalityDiagnosticsExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v *CriticalityDiagnosticsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldReceived(v *CriticalityDiagnosticsExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldReplay(v *CriticalityDiagnosticsExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldStream(v *CriticalityDiagnosticsExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldWithoutReplay(v *CriticalityDiagnosticsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReceived(v *CriticalityDiagnosticsIEListExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReplay(v *CriticalityDiagnosticsIEListExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldStream(v *CriticalityDiagnosticsIEListExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldWithoutReplay(v *CriticalityDiagnosticsIEListExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsIEListExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEListExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldReceived(v *CriticalityDiagnosticsIEListExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldReplay(v *CriticalityDiagnosticsIEListExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldStream(v *CriticalityDiagnosticsIEListExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldWithoutReplay(v *CriticalityDiagnosticsIEListExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsIEListExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEListExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECGIExtIEsExtFieldFieldReceived(v *ECGIExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeECGIExtIEsExtFieldFieldReplay(v *ECGIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeECGIExtIEsExtFieldFieldStream(v *ECGIExtIEsExtField) *aper.WireSpan { return &v.stream }
func BridgeECGIExtIEsExtFieldFieldWithoutReplay(v *ECGIExtIEsExtField) *bool   { return &v.withoutReplay }
func BridgeECGIExtIEsExtFieldMethodMarshalAPERTo(v *ECGIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECGIExtIEsExtFieldMethodUnmarshalAPERFrom(v *ECGIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECGIExtIEsIEFieldFieldReceived(v *ECGIExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeECGIExtIEsIEFieldFieldReplay(v *ECGIExtIEsIEField) *aper.Snapshot { return &v.replay }
func BridgeECGIExtIEsIEFieldFieldStream(v *ECGIExtIEsIEField) *aper.WireSpan { return &v.stream }
func BridgeECGIExtIEsIEFieldFieldWithoutReplay(v *ECGIExtIEsIEField) *bool   { return &v.withoutReplay }
func BridgeECGIExtIEsIEFieldMethodMarshalAPERTo(v *ECGIExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECGIExtIEsIEFieldMethodUnmarshalAPERFrom(v *ECGIExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldReceived(v *ECIDMeasurementTerminationCommandIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldReplay(v *ECIDMeasurementTerminationCommandIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldStream(v *ECIDMeasurementTerminationCommandIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldWithoutReplay(v *ECIDMeasurementTerminationCommandIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementTerminationCommandIEFieldMethodMarshalAPERTo(v *ECIDMeasurementTerminationCommandIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementTerminationCommandIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementTerminationCommandIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementTerminationCommandIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementTerminationCommandIETable) s00.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementTerminationCommandIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementTerminationCommandIETable) s00.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *s00.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldGet(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *func(*s02.ECIDMeasurementTerminationCommandIEValue) (*s00.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldInject(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *func(s00.MeasurementID) s02.ECIDMeasurementTerminationCommandIEValue {
	return &v.inject
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReceived(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(v *InterRATMeasurementQuantitiesValueExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(v *InterRATMeasurementQuantitiesValueExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsExtIEsValueFieldId(v *PosSIBsExtIEsValue) *s00.ProtocolIEID { return &v.id }
func BridgePosSIBsExtIEsValueFieldIsOpaque(v *PosSIBsExtIEsValue) *bool       { return &v.isOpaque }
func BridgePosSIBsExtIEsValueFieldOpaque(v *PosSIBsExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePosSIBsExtIEsValueFieldReceived(v *PosSIBsExtIEsValue) *aper.WireSpan { return &v.received }
func BridgePosSIBsExtIEsValueFieldReplay(v *PosSIBsExtIEsValue) *aper.Snapshot   { return &v.replay }
func BridgePosSIBsExtIEsValueFieldWithoutReplay(v *PosSIBsExtIEsValue) *bool     { return &v.withoutReplay }
func BridgePosSIBsExtIEsValueMethodCaptureFraming(v PosSIBsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePosSIBsExtIEsValueMethodCaptureSemantics(v PosSIBsExtIEsValue, a0 aper.SemanticCapture) PosSIBsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgePosSIBsExtIEsValueMethodCaptureSnapshot(v PosSIBsExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgePosSIBsExtIEsValueMethodCompareSemantics(v PosSIBsExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePosSIBsExtIEsValueMethodDecode(v PosSIBsExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PosSIBsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePosSIBsExtIEsValueMethodEncode(v PosSIBsExtIEsValue) ([]byte, error) { return v.encode() }
func BridgePosSIBsExtIEsValueMethodEncodeFresh(v PosSIBsExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePosSIBsExtIEsValueMethodMatchesID(v PosSIBsExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePosSIBsExtIEsValueMethodReason(v PosSIBsExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePosSIBsExtIEsValueMethodRule(v PosSIBsExtIEsValue) aper.SourceRule { return v.rule() }
func BridgeResultGERANItemExtIEsValueFieldId(v *ResultGERANItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeResultGERANItemExtIEsValueFieldIsOpaque(v *ResultGERANItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultGERANItemExtIEsValueFieldOpaque(v *ResultGERANItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultGERANItemExtIEsValueFieldReceived(v *ResultGERANItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultGERANItemExtIEsValueFieldReplay(v *ResultGERANItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemExtIEsValueFieldWithoutReplay(v *ResultGERANItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemExtIEsValueMethodCaptureFraming(v ResultGERANItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultGERANItemExtIEsValueMethodCaptureSemantics(v ResultGERANItemExtIEsValue, a0 aper.SemanticCapture) ResultGERANItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultGERANItemExtIEsValueMethodCaptureSnapshot(v ResultGERANItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultGERANItemExtIEsValueMethodCompareSemantics(v ResultGERANItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultGERANItemExtIEsValueMethodDecode(v ResultGERANItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResultGERANItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultGERANItemExtIEsValueMethodEncode(v ResultGERANItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultGERANItemExtIEsValueMethodEncodeFresh(v ResultGERANItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultGERANItemExtIEsValueMethodMatchesID(v ResultGERANItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultGERANItemExtIEsValueMethodReason(v ResultGERANItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultGERANItemExtIEsValueMethodRule(v ResultGERANItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeResultRSRPItemExtIEsValueFieldId(v *ResultRSRPItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeResultRSRPItemExtIEsValueFieldIsOpaque(v *ResultRSRPItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultRSRPItemExtIEsValueFieldOpaque(v *ResultRSRPItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultRSRPItemExtIEsValueFieldReceived(v *ResultRSRPItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultRSRPItemExtIEsValueFieldReplay(v *ResultRSRPItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemExtIEsValueFieldWithoutReplay(v *ResultRSRPItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemExtIEsValueMethodCaptureFraming(v ResultRSRPItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultRSRPItemExtIEsValueMethodCaptureSemantics(v ResultRSRPItemExtIEsValue, a0 aper.SemanticCapture) ResultRSRPItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultRSRPItemExtIEsValueMethodCaptureSnapshot(v ResultRSRPItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultRSRPItemExtIEsValueMethodCompareSemantics(v ResultRSRPItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultRSRPItemExtIEsValueMethodDecode(v ResultRSRPItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResultRSRPItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultRSRPItemExtIEsValueMethodEncode(v ResultRSRPItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultRSRPItemExtIEsValueMethodEncodeFresh(v ResultRSRPItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultRSRPItemExtIEsValueMethodMatchesID(v ResultRSRPItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultRSRPItemExtIEsValueMethodReason(v ResultRSRPItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultRSRPItemExtIEsValueMethodRule(v ResultRSRPItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeResultRSRQItemExtIEsValueFieldId(v *ResultRSRQItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeResultRSRQItemExtIEsValueFieldIsOpaque(v *ResultRSRQItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultRSRQItemExtIEsValueFieldOpaque(v *ResultRSRQItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultRSRQItemExtIEsValueFieldReceived(v *ResultRSRQItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultRSRQItemExtIEsValueFieldReplay(v *ResultRSRQItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemExtIEsValueFieldWithoutReplay(v *ResultRSRQItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemExtIEsValueMethodCaptureFraming(v ResultRSRQItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultRSRQItemExtIEsValueMethodCaptureSemantics(v ResultRSRQItemExtIEsValue, a0 aper.SemanticCapture) ResultRSRQItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultRSRQItemExtIEsValueMethodCaptureSnapshot(v ResultRSRQItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultRSRQItemExtIEsValueMethodCompareSemantics(v ResultRSRQItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultRSRQItemExtIEsValueMethodDecode(v ResultRSRQItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResultRSRQItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultRSRQItemExtIEsValueMethodEncode(v ResultRSRQItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultRSRQItemExtIEsValueMethodEncodeFresh(v ResultRSRQItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultRSRQItemExtIEsValueMethodMatchesID(v ResultRSRQItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultRSRQItemExtIEsValueMethodReason(v ResultRSRQItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultRSRQItemExtIEsValueMethodRule(v ResultRSRQItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeResultUTRANItemExtIEsValueFieldId(v *ResultUTRANItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeResultUTRANItemExtIEsValueFieldIsOpaque(v *ResultUTRANItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultUTRANItemExtIEsValueFieldOpaque(v *ResultUTRANItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultUTRANItemExtIEsValueFieldReceived(v *ResultUTRANItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultUTRANItemExtIEsValueFieldReplay(v *ResultUTRANItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemExtIEsValueFieldWithoutReplay(v *ResultUTRANItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemExtIEsValueMethodCaptureFraming(v ResultUTRANItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultUTRANItemExtIEsValueMethodCaptureSemantics(v ResultUTRANItemExtIEsValue, a0 aper.SemanticCapture) ResultUTRANItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultUTRANItemExtIEsValueMethodCaptureSnapshot(v ResultUTRANItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultUTRANItemExtIEsValueMethodCompareSemantics(v ResultUTRANItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultUTRANItemExtIEsValueMethodDecode(v ResultUTRANItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResultUTRANItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultUTRANItemExtIEsValueMethodEncode(v ResultUTRANItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultUTRANItemExtIEsValueMethodEncodeFresh(v ResultUTRANItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultUTRANItemExtIEsValueMethodMatchesID(v ResultUTRANItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultUTRANItemExtIEsValueMethodReason(v ResultUTRANItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultUTRANItemExtIEsValueMethodRule(v ResultUTRANItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldId(v *ResultsPerSSBIndexItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldIsOpaque(v *ResultsPerSSBIndexItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldOpaque(v *ResultsPerSSBIndexItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldReceived(v *ResultsPerSSBIndexItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldReplay(v *ResultsPerSSBIndexItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldWithoutReplay(v *ResultsPerSSBIndexItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureFraming(v ResultsPerSSBIndexItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSemantics(v ResultsPerSSBIndexItemExtIEsValue, a0 aper.SemanticCapture) ResultsPerSSBIndexItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSnapshot(v ResultsPerSSBIndexItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCompareSemantics(v ResultsPerSSBIndexItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodDecode(v ResultsPerSSBIndexItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResultsPerSSBIndexItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodEncode(v ResultsPerSSBIndexItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodEncodeFresh(v ResultsPerSSBIndexItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(v ResultsPerSSBIndexItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodReason(v ResultsPerSSBIndexItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(v ResultsPerSSBIndexItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeSystemInformationExtIEsValueFieldId(v *SystemInformationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSystemInformationExtIEsValueFieldIsOpaque(v *SystemInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeSystemInformationExtIEsValueFieldOpaque(v *SystemInformationExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSystemInformationExtIEsValueFieldReceived(v *SystemInformationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeSystemInformationExtIEsValueFieldReplay(v *SystemInformationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSystemInformationExtIEsValueFieldWithoutReplay(v *SystemInformationExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationExtIEsValueMethodCaptureFraming(v SystemInformationExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeSystemInformationExtIEsValueMethodCaptureSemantics(v SystemInformationExtIEsValue, a0 aper.SemanticCapture) SystemInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeSystemInformationExtIEsValueMethodCaptureSnapshot(v SystemInformationExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeSystemInformationExtIEsValueMethodCompareSemantics(v SystemInformationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSystemInformationExtIEsValueMethodDecode(v SystemInformationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SystemInformationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeSystemInformationExtIEsValueMethodEncode(v SystemInformationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeSystemInformationExtIEsValueMethodEncodeFresh(v SystemInformationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSystemInformationExtIEsValueMethodMatchesID(v SystemInformationExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeSystemInformationExtIEsValueMethodReason(v SystemInformationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSystemInformationExtIEsValueMethodRule(v SystemInformationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeTDDConfigurationExtIEsValueFieldId(v *TDDConfigurationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeTDDConfigurationExtIEsValueFieldIsOpaque(v *TDDConfigurationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeTDDConfigurationExtIEsValueFieldOpaque(v *TDDConfigurationExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeTDDConfigurationExtIEsValueFieldReceived(v *TDDConfigurationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeTDDConfigurationExtIEsValueFieldReplay(v *TDDConfigurationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationExtIEsValueFieldWithoutReplay(v *TDDConfigurationExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationExtIEsValueMethodCaptureFraming(v TDDConfigurationExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeTDDConfigurationExtIEsValueMethodCaptureSemantics(v TDDConfigurationExtIEsValue, a0 aper.SemanticCapture) TDDConfigurationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeTDDConfigurationExtIEsValueMethodCaptureSnapshot(v TDDConfigurationExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeTDDConfigurationExtIEsValueMethodCompareSemantics(v TDDConfigurationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeTDDConfigurationExtIEsValueMethodDecode(v TDDConfigurationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (TDDConfigurationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeTDDConfigurationExtIEsValueMethodEncode(v TDDConfigurationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeTDDConfigurationExtIEsValueMethodEncodeFresh(v TDDConfigurationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeTDDConfigurationExtIEsValueMethodMatchesID(v TDDConfigurationExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeTDDConfigurationExtIEsValueMethodReason(v TDDConfigurationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeTDDConfigurationExtIEsValueMethodRule(v TDDConfigurationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldId(v *WLANMeasurementQuantitiesValueExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(v *WLANMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldOpaque(v *WLANMeasurementQuantitiesValueExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldReceived(v *WLANMeasurementQuantitiesValueExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldReplay(v *WLANMeasurementQuantitiesValueExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldWithoutReplay(v *WLANMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v WLANMeasurementQuantitiesValueExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v WLANMeasurementQuantitiesValueExtIEsValue, a0 aper.SemanticCapture) WLANMeasurementQuantitiesValueExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v WLANMeasurementQuantitiesValueExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v WLANMeasurementQuantitiesValueExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodDecode(v WLANMeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (WLANMeasurementQuantitiesValueExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncode(v WLANMeasurementQuantitiesValueExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v WLANMeasurementQuantitiesValueExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v WLANMeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodReason(v WLANMeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodRule(v WLANMeasurementQuantitiesValueExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldId(v *WLANMeasurementResultItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldIsOpaque(v *WLANMeasurementResultItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldOpaque(v *WLANMeasurementResultItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldReceived(v *WLANMeasurementResultItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldReplay(v *WLANMeasurementResultItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldWithoutReplay(v *WLANMeasurementResultItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureFraming(v WLANMeasurementResultItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureSemantics(v WLANMeasurementResultItemExtIEsValue, a0 aper.SemanticCapture) WLANMeasurementResultItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureSnapshot(v WLANMeasurementResultItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCompareSemantics(v WLANMeasurementResultItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodDecode(v WLANMeasurementResultItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (WLANMeasurementResultItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodEncode(v WLANMeasurementResultItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodEncodeFresh(v WLANMeasurementResultItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(v WLANMeasurementResultItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodReason(v WLANMeasurementResultItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodRule(v WLANMeasurementResultItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
