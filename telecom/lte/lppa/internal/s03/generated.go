// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s03 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s03

import (
	q7 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementTerminationCommandIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEContainer []ECIDMeasurementTerminationCommandIEField

// ECIDMeasurementTerminationCommandIEField is the concrete ProtocolIEField[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.ECIDMeasurementTerminationCommandIEValue

	received q4.CompletePadding
}

func (v ECIDMeasurementTerminationCommandIEField) WithoutReplay() ECIDMeasurementTerminationCommandIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ECIDMeasurementTerminationCommandIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementTerminationCommandIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeECIDMeasurementTerminationCommandIEValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ECIDMeasurementTerminationCommandIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementTerminationCommandIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.ECIDMeasurementTerminationCommandIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeECIDMeasurementTerminationCommandIEValueMethodReason(zero, v.Id), q6.BridgeECIDMeasurementTerminationCommandIEValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsExtContainer []AssistanceInformationExtIEsExtField

// AssistanceInformationMetaDataExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsExtContainer []AssistanceInformationMetaDataExtIEsExtField

// CriticalityDiagnosticsExtIEsExtContainer is the concrete ProtocolExtensionContainer[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsExtContainer []CriticalityDiagnosticsExtIEsExtField

// ECGIExtIEsExtContainer is the concrete ProtocolExtensionContainer[ECGIExtIEsValue].
type ECGIExtIEsExtContainer []ECGIExtIEsExtField

// InterRATMeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsExtContainer []InterRATMeasurementQuantitiesValueExtIEsExtField

// AddOTDOACellsExtIEsExtContainer is the concrete ProtocolExtensionContainer[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsExtContainer []AddOTDOACellsExtIEsExtField

// AssistanceInformationFailureListExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsExtContainer []AssistanceInformationFailureListExtIEsExtField

// CriticalityDiagnosticsIEListExtIEsExtContainer is the concrete ProtocolExtensionContainer[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsExtContainer []CriticalityDiagnosticsIEListExtIEsExtField

// AssistanceInformationExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.AssistanceInformationExtIEsValue

	received q4.CompletePadding
}

func (v AssistanceInformationExtIEsExtField) WithoutReplay() AssistanceInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAssistanceInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAssistanceInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AssistanceInformationExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AssistanceInformationExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAssistanceInformationExtIEsValueMethodReason(zero, v.Id), q6.BridgeAssistanceInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeAssistanceInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationMetaDataExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.AssistanceInformationMetaDataExtIEsValue

	received q4.CompletePadding
}

func (v AssistanceInformationMetaDataExtIEsExtField) WithoutReplay() AssistanceInformationMetaDataExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationMetaDataExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationMetaDataExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AssistanceInformationMetaDataExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationMetaDataExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AssistanceInformationMetaDataExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodReason(zero, v.Id), q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsExtIEsExtField is the concrete ProtocolExtensionField[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.CriticalityDiagnosticsExtIEsValue

	received q4.CompletePadding
}

func (v CriticalityDiagnosticsExtIEsExtField) WithoutReplay() CriticalityDiagnosticsExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *CriticalityDiagnosticsExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.CriticalityDiagnosticsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeCriticalityDiagnosticsExtIEsValueMethodReason(zero, v.Id), q6.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECGIExtIEsExtField is the concrete ProtocolExtensionField[ECGIExtIEsValue].
type ECGIExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.ECGIExtIEsValue

	received q4.CompletePadding
}

func (v ECGIExtIEsExtField) WithoutReplay() ECGIExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ECGIExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECGIExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeECGIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeECGIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ECGIExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECGIExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.ECGIExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeECGIExtIEsValueMethodReason(zero, v.Id), q6.BridgeECGIExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeECGIExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// InterRATMeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.InterRATMeasurementQuantitiesValueExtIEsValue

	received q4.CompletePadding
}

func (v InterRATMeasurementQuantitiesValueExtIEsExtField) WithoutReplay() InterRATMeasurementQuantitiesValueExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *InterRATMeasurementQuantitiesValueExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *InterRATMeasurementQuantitiesValueExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *InterRATMeasurementQuantitiesValueExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasurementQuantitiesValueExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.InterRATMeasurementQuantitiesValueExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AddOTDOACellsExtIEsExtField is the concrete ProtocolExtensionField[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.AddOTDOACellsExtIEsValue

	received q4.CompletePadding
}

func (v AddOTDOACellsExtIEsExtField) WithoutReplay() AddOTDOACellsExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AddOTDOACellsExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AddOTDOACellsExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAddOTDOACellsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAddOTDOACellsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AddOTDOACellsExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AddOTDOACellsExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AddOTDOACellsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAddOTDOACellsExtIEsValueMethodReason(zero, v.Id), q6.BridgeAddOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeAddOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationFailureListExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.AssistanceInformationFailureListExtIEsValue

	received q4.CompletePadding
}

func (v AssistanceInformationFailureListExtIEsExtField) WithoutReplay() AssistanceInformationFailureListExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationFailureListExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationFailureListExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAssistanceInformationFailureListExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *AssistanceInformationFailureListExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFailureListExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AssistanceInformationFailureListExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAssistanceInformationFailureListExtIEsValueMethodReason(zero, v.Id), q6.BridgeAssistanceInformationFailureListExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeAssistanceInformationFailureListExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsIEListExtIEsExtField is the concrete ProtocolExtensionField[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.CriticalityDiagnosticsIEListExtIEsValue

	received q4.CompletePadding
}

func (v CriticalityDiagnosticsIEListExtIEsExtField) WithoutReplay() CriticalityDiagnosticsIEListExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *CriticalityDiagnosticsIEListExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsIEListExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsIEListExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEListExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.CriticalityDiagnosticsIEListExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodReason(zero, v.Id), q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECIDMeasurementTerminationCommandMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandMeasurementIDIEBinding struct {
	info   q5.FieldInfo
	codec  q5.MeasurementIDValueCodec
	inject func(q5.MeasurementID,

	) q6.ECIDMeasurementTerminationCommandIEValue

	get func(*q6.ECIDMeasurementTerminationCommandIEValue,

	) (*q5.MeasurementID,

		bool)
}

func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) Codec() q5.MeasurementIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) New(value q5.MeasurementID,

) (ECIDMeasurementTerminationCommandIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(q7.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(q7.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementTerminationCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementTerminationCommandMeasurementIDIEBinding) Get(field *ECIDMeasurementTerminationCommandIEField) (*q5.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// addOTDOACellsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.AddOTDOACellsExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.AddOTDOACellsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// assistanceInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.AssistanceInformationExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.AssistanceInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// assistanceInformationFailureListExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.AssistanceInformationFailureListExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.AssistanceInformationFailureListExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// assistanceInformationMetaDataExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.AssistanceInformationMetaDataExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.AssistanceInformationMetaDataExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// criticalityDiagnosticsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.CriticalityDiagnosticsExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.CriticalityDiagnosticsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// criticalityDiagnosticsIEListExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.CriticalityDiagnosticsIEListExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.CriticalityDiagnosticsIEListExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// eCGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ECGIExtIEsValue].
type ECGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.ECGIExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.ECGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// eCIDMeasurementTerminationCommandIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.ECIDMeasurementTerminationCommandIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.ECIDMeasurementTerminationCommandIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// AddOTDOACellsExtIEsIEField is the concrete ProtocolIEField[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.AddOTDOACellsExtIEsValue

	received q4.CompletePadding
}

func (v AddOTDOACellsExtIEsIEField) WithoutReplay() AddOTDOACellsExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AddOTDOACellsExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AddOTDOACellsExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAddOTDOACellsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAddOTDOACellsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AddOTDOACellsExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AddOTDOACellsExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AddOTDOACellsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAddOTDOACellsExtIEsValueMethodReason(zero, v.Id), q6.BridgeAddOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeAddOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AddOTDOACellsExtIEsIEContainer is the concrete ProtocolIEContainer[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsIEContainer []AddOTDOACellsExtIEsIEField

// AssistanceInformationExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.AssistanceInformationExtIEsValue

	received q4.CompletePadding
}

func (v AssistanceInformationExtIEsIEField) WithoutReplay() AssistanceInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAssistanceInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAssistanceInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AssistanceInformationExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AssistanceInformationExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAssistanceInformationExtIEsValueMethodReason(zero, v.Id), q6.BridgeAssistanceInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeAssistanceInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsIEContainer []AssistanceInformationExtIEsIEField

// AssistanceInformationFailureListExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.AssistanceInformationFailureListExtIEsValue

	received q4.CompletePadding
}

func (v AssistanceInformationFailureListExtIEsIEField) WithoutReplay() AssistanceInformationFailureListExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationFailureListExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationFailureListExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAssistanceInformationFailureListExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AssistanceInformationFailureListExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFailureListExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AssistanceInformationFailureListExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAssistanceInformationFailureListExtIEsValueMethodReason(zero, v.Id), q6.BridgeAssistanceInformationFailureListExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeAssistanceInformationFailureListExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationFailureListExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsIEContainer []AssistanceInformationFailureListExtIEsIEField

// AssistanceInformationMetaDataExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.AssistanceInformationMetaDataExtIEsValue

	received q4.CompletePadding
}

func (v AssistanceInformationMetaDataExtIEsIEField) WithoutReplay() AssistanceInformationMetaDataExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationMetaDataExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationMetaDataExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AssistanceInformationMetaDataExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationMetaDataExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.AssistanceInformationMetaDataExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodReason(zero, v.Id), q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// AssistanceInformationMetaDataExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsIEContainer []AssistanceInformationMetaDataExtIEsIEField

// CriticalityDiagnosticsExtIEsIEField is the concrete ProtocolIEField[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.CriticalityDiagnosticsExtIEsValue

	received q4.CompletePadding
}

func (v CriticalityDiagnosticsExtIEsIEField) WithoutReplay() CriticalityDiagnosticsExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *CriticalityDiagnosticsExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.CriticalityDiagnosticsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeCriticalityDiagnosticsExtIEsValueMethodReason(zero, v.Id), q6.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsExtIEsIEContainer is the concrete ProtocolIEContainer[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsIEContainer []CriticalityDiagnosticsExtIEsIEField

// CriticalityDiagnosticsIEListExtIEsIEField is the concrete ProtocolIEField[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.CriticalityDiagnosticsIEListExtIEsValue

	received q4.CompletePadding
}

func (v CriticalityDiagnosticsIEListExtIEsIEField) WithoutReplay() CriticalityDiagnosticsIEListExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *CriticalityDiagnosticsIEListExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *CriticalityDiagnosticsIEListExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *CriticalityDiagnosticsIEListExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEListExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.CriticalityDiagnosticsIEListExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodReason(zero, v.Id), q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// CriticalityDiagnosticsIEListExtIEsIEContainer is the concrete ProtocolIEContainer[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsIEContainer []CriticalityDiagnosticsIEListExtIEsIEField

// ECGIExtIEsIEField is the concrete ProtocolIEField[ECGIExtIEsValue].
type ECGIExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.ECGIExtIEsValue

	received q4.CompletePadding
}

func (v ECGIExtIEsIEField) WithoutReplay() ECGIExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ECGIExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECGIExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeECGIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeECGIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ECGIExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECGIExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.ECGIExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeECGIExtIEsValueMethodReason(zero, v.Id), q6.BridgeECGIExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeECGIExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECGIExtIEsIEContainer is the concrete ProtocolIEContainer[ECGIExtIEsValue].
type ECGIExtIEsIEContainer []ECGIExtIEsIEField

// InterRATMeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.InterRATMeasurementQuantitiesValueExtIEsValue

	received q4.CompletePadding
}

func (v InterRATMeasurementQuantitiesValueExtIEsIEField) WithoutReplay() InterRATMeasurementQuantitiesValueExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *InterRATMeasurementQuantitiesValueExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *InterRATMeasurementQuantitiesValueExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *InterRATMeasurementQuantitiesValueExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasurementQuantitiesValueExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.InterRATMeasurementQuantitiesValueExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// InterRATMeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsIEContainer []InterRATMeasurementQuantitiesValueExtIEsIEField

func BridgeEffectivePayloadLimits(l q5.PayloadLimits) q5.PayloadLimits {
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
func BridgeCaptureLPPaPosSIBsExtIEsValue(v *PosSIBsExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v PosSIBsExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v PosSIBsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v PosSIBsExtIEsValue) captureSemantics(s q4.SemanticCapture) PosSIBsExtIEsValue {
	BridgeCaptureLPPaPosSIBsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPosSIBsExtIEsValue(v *PosSIBsExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v PosSIBsExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaPosSIBsExtIEsValue(&v, &s)
	return s
}
func (v PosSIBsExtIEsValue) WithoutReplay() PosSIBsExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCompareLPPaRSSI(v *q5.RSSI, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCompareLPPaRepetitionNumberofSIB1NB(v *q5.RepetitionNumberofSIB1NB, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaReportCharacteristics(v *q5.ReportCharacteristics, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaResultGERANItemExtIEsValue(v *ResultGERANItemExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v ResultGERANItemExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ResultGERANItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultGERANItemExtIEsValue) captureSemantics(s q4.SemanticCapture) ResultGERANItemExtIEsValue {
	BridgeCaptureLPPaResultGERANItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultGERANItemExtIEsValue(v *ResultGERANItemExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultGERANItemExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaResultGERANItemExtIEsValue(&v, &s)
	return s
}
func (v ResultGERANItemExtIEsValue) WithoutReplay() ResultGERANItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultRSRPItemExtIEsValue(v *ResultRSRPItemExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v ResultRSRPItemExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ResultRSRPItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultRSRPItemExtIEsValue) captureSemantics(s q4.SemanticCapture) ResultRSRPItemExtIEsValue {
	BridgeCaptureLPPaResultRSRPItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultRSRPItemExtIEsValue(v *ResultRSRPItemExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultRSRPItemExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaResultRSRPItemExtIEsValue(&v, &s)
	return s
}
func (v ResultRSRPItemExtIEsValue) WithoutReplay() ResultRSRPItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultRSRQItemExtIEsValue(v *ResultRSRQItemExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v ResultRSRQItemExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ResultRSRQItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultRSRQItemExtIEsValue) captureSemantics(s q4.SemanticCapture) ResultRSRQItemExtIEsValue {
	BridgeCaptureLPPaResultRSRQItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultRSRQItemExtIEsValue(v *ResultRSRQItemExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultRSRQItemExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaResultRSRQItemExtIEsValue(&v, &s)
	return s
}
func (v ResultRSRQItemExtIEsValue) WithoutReplay() ResultRSRQItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultUTRANItemExtIEsValue(v *ResultUTRANItemExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v ResultUTRANItemExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ResultUTRANItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultUTRANItemExtIEsValue) captureSemantics(s q4.SemanticCapture) ResultUTRANItemExtIEsValue {
	BridgeCaptureLPPaResultUTRANItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultUTRANItemExtIEsValue(v *ResultUTRANItemExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultUTRANItemExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaResultUTRANItemExtIEsValue(&v, &s)
	return s
}
func (v ResultUTRANItemExtIEsValue) WithoutReplay() ResultUTRANItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultsPerSSBIndexItemExtIEsValue(v *ResultsPerSSBIndexItemExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v ResultsPerSSBIndexItemExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ResultsPerSSBIndexItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultsPerSSBIndexItemExtIEsValue) captureSemantics(s q4.SemanticCapture) ResultsPerSSBIndexItemExtIEsValue {
	BridgeCaptureLPPaResultsPerSSBIndexItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultsPerSSBIndexItemExtIEsValue(v *ResultsPerSSBIndexItemExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultsPerSSBIndexItemExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaResultsPerSSBIndexItemExtIEsValue(&v, &s)
	return s
}
func (v ResultsPerSSBIndexItemExtIEsValue) WithoutReplay() ResultsPerSSBIndexItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCompareLPPaSFNInitialisationTime(v *q5.SFNInitialisationTime, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCompareLPPaSSBIndex(v *q5.SSBIndex, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaSSID(v *q5.SSID, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaSSNRRSRP(v *q5.SSNRRSRP, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaSSNRRSRQ(v *q5.SSNRRSRQ, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaSystemInformationExtIEsValue(v *SystemInformationExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v SystemInformationExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v SystemInformationExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v SystemInformationExtIEsValue) captureSemantics(s q4.SemanticCapture) SystemInformationExtIEsValue {
	BridgeCaptureLPPaSystemInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaSystemInformationExtIEsValue(v *SystemInformationExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v SystemInformationExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaSystemInformationExtIEsValue(&v, &s)
	return s
}
func (v SystemInformationExtIEsValue) WithoutReplay() SystemInformationExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCompareLPPaTAC(v *q5.TAC, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCaptureLPPaTDDConfigurationExtIEsValue(v *TDDConfigurationExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v TDDConfigurationExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v TDDConfigurationExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v TDDConfigurationExtIEsValue) captureSemantics(s q4.SemanticCapture) TDDConfigurationExtIEsValue {
	BridgeCaptureLPPaTDDConfigurationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaTDDConfigurationExtIEsValue(v *TDDConfigurationExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v TDDConfigurationExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaTDDConfigurationExtIEsValue(&v, &s)
	return s
}
func (v TDDConfigurationExtIEsValue) WithoutReplay() TDDConfigurationExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCompareLPPaTPID(v *q5.TPID, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCompareLPPaTPType(v *q5.TPType, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaTriggeringMessage(v *q5.TriggeringMessage, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaTypeOfError(v *q5.TypeOfError, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaUARFCN(v *q5.UARFCN, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCompareLPPaUTRAEcN0(v *q5.UTRAEcN0, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCompareLPPaUTRARSCP(v *q5.UTRARSCP, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCompareLPPaValueRSRP(v *q5.ValueRSRP, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCompareLPPaValueRSRQ(v *q5.ValueRSRQ, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCompareLPPaWLANBand(v *q5.WLANBand, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANChannel(v *q5.WLANChannel, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANChannelList(v *q5.WLANChannelList, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCompareLPPaWLANCountryCode(v *q5.WLANCountryCode, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANMeasurementQuantitiesValue(v *q5.WLANMeasurementQuantitiesValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesValueExtIEsValue(v *WLANMeasurementQuantitiesValueExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v WLANMeasurementQuantitiesValueExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v WLANMeasurementQuantitiesValueExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) captureSemantics(s q4.SemanticCapture) WLANMeasurementQuantitiesValueExtIEsValue {
	BridgeCaptureLPPaWLANMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaWLANMeasurementQuantitiesValueExtIEsValue(v *WLANMeasurementQuantitiesValueExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaWLANMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return s
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) WithoutReplay() WLANMeasurementQuantitiesValueExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaWLANMeasurementResultItemExtIEsValue(v *WLANMeasurementResultItemExtIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
func (v WLANMeasurementResultItemExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v WLANMeasurementResultItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v WLANMeasurementResultItemExtIEsValue) captureSemantics(s q4.SemanticCapture) WLANMeasurementResultItemExtIEsValue {
	BridgeCaptureLPPaWLANMeasurementResultItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaWLANMeasurementResultItemExtIEsValue(v *WLANMeasurementResultItemExtIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q6.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v WLANMeasurementResultItemExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaWLANMeasurementResultItemExtIEsValue(&v, &s)
	return s
}
func (v WLANMeasurementResultItemExtIEsValue) WithoutReplay() WLANMeasurementResultItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCompareLPPaWLANOperatingClass(v *q5.WLANOperatingClass, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaWLANRSSI(v *q5.WLANRSSI, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q4.Snapshot{}, false)
	}
}

type PosSIBsExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v PosSIBsExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *PosSIBsExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (PosSIBsExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIBs-ExtIEs"}}
}
func (PosSIBsExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v PosSIBsExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (PosSIBsExtIEsValue, error) {
	out := PosSIBsExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PosSIBsExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "PosSIBsExtIEsValue:", v.id)
	}
}

type ResultGERANItemExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v ResultGERANItemExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *ResultGERANItemExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultGERANItemExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultGERAN-Item-ExtIEs"}}
}
func (ResultGERANItemExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v ResultGERANItemExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ResultGERANItemExtIEsValue, error) {
	out := ResultGERANItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultGERANItemExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "ResultGERANItemExtIEsValue:", v.id)
	}
}

type ResultRSRPItemExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v ResultRSRPItemExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *ResultRSRPItemExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultRSRPItemExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRP-Item-ExtIEs"}}
}
func (ResultRSRPItemExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v ResultRSRPItemExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ResultRSRPItemExtIEsValue, error) {
	out := ResultRSRPItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultRSRPItemExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "ResultRSRPItemExtIEsValue:", v.id)
	}
}

type ResultRSRQItemExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v ResultRSRQItemExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *ResultRSRQItemExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultRSRQItemExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRQ-Item-ExtIEs"}}
}
func (ResultRSRQItemExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v ResultRSRQItemExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ResultRSRQItemExtIEsValue, error) {
	out := ResultRSRQItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultRSRQItemExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "ResultRSRQItemExtIEsValue:", v.id)
	}
}

type ResultUTRANItemExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v ResultUTRANItemExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *ResultUTRANItemExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultUTRANItemExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultUTRAN-Item-ExtIEs"}}
}
func (ResultUTRANItemExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v ResultUTRANItemExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ResultUTRANItemExtIEsValue, error) {
	out := ResultUTRANItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultUTRANItemExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "ResultUTRANItemExtIEsValue:", v.id)
	}
}

type ResultsPerSSBIndexItemExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v ResultsPerSSBIndexItemExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *ResultsPerSSBIndexItemExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultsPerSSBIndexItemExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultsPerSSB-Index-Item-ExtIEs"}}
}
func (ResultsPerSSBIndexItemExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v ResultsPerSSBIndexItemExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ResultsPerSSBIndexItemExtIEsValue, error) {
	out := ResultsPerSSBIndexItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultsPerSSBIndexItemExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "ResultsPerSSBIndexItemExtIEsValue:", v.id)
	}
}

type SystemInformationExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v SystemInformationExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *SystemInformationExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (SystemInformationExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "SystemInformation-ExtIEs"}}
}
func (SystemInformationExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v SystemInformationExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (SystemInformationExtIEsValue, error) {
	out := SystemInformationExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v SystemInformationExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "SystemInformationExtIEsValue:", v.id)
	}
}

type TDDConfigurationExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v TDDConfigurationExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *TDDConfigurationExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (TDDConfigurationExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "TDDConfiguration-ExtIEs"}}
}
func (TDDConfigurationExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v TDDConfigurationExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (TDDConfigurationExtIEsValue, error) {
	out := TDDConfigurationExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v TDDConfigurationExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "TDDConfigurationExtIEsValue:", v.id)
	}
}

type WLANMeasurementQuantitiesValueExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v WLANMeasurementQuantitiesValueExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *WLANMeasurementQuantitiesValueExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (WLANMeasurementQuantitiesValueExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantitiesValue-ExtIEs"}}
}
func (WLANMeasurementQuantitiesValueExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (WLANMeasurementQuantitiesValueExtIEsValue, error) {
	out := WLANMeasurementQuantitiesValueExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v WLANMeasurementQuantitiesValueExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "WLANMeasurementQuantitiesValueExtIEsValue:", v.id)
	}
}

type WLANMeasurementResultItemExtIEsValue struct {
	id            q5.ProtocolIEID
	withoutReplay bool
	received      q4.WireSpan
	replay        q4.Snapshot
	opaque        *q4.OpaqueOpenType
	isOpaque      bool
}

func (v WLANMeasurementResultItemExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
func (v *WLANMeasurementResultItemExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (WLANMeasurementResultItemExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementResult-Item-ExtIEs"}}
}
func (WLANMeasurementResultItemExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v WLANMeasurementResultItemExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (WLANMeasurementResultItemExtIEsValue, error) {
	out := WLANMeasurementResultItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v WLANMeasurementResultItemExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	default:
		return nil, q7.Errorf("%s id %d has no value", "WLANMeasurementResultItemExtIEsValue:", v.id)
	}
}

type AddOTDOACellsExtIETable struct{}

func AddOTDOACellsExtIEs() AddOTDOACellsExtIETable { return AddOTDOACellsExtIETable{} }
func (AddOTDOACellsExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Add-OTDOACells-ExtIEs"}
		return sealed
	}()
}
func (t AddOTDOACellsExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (AddOTDOACellsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AddOTDOACellsExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return AddOTDOACellsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AddOTDOACellsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AddOTDOACellsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return AddOTDOACellsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.AddOTDOACellsExtIEsValue {
			sealed := q6.AddOTDOACellsExtIEsValue{}
			*q6.BridgeAddOTDOACellsExtIEsValueFieldId(&sealed) = id
			*q6.BridgeAddOTDOACellsExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeAddOTDOACellsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type AssistanceInformationExtIETable struct{}

func AssistanceInformationExtIEs() AssistanceInformationExtIETable {
	return AssistanceInformationExtIETable{}
}
func (AssistanceInformationExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Assistance-Information-ExtIEs"}
		return sealed
	}()
}
func (t AssistanceInformationExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (AssistanceInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return AssistanceInformationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return AssistanceInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.AssistanceInformationExtIEsValue {
			sealed := q6.AssistanceInformationExtIEsValue{}
			*q6.BridgeAssistanceInformationExtIEsValueFieldId(&sealed) = id
			*q6.BridgeAssistanceInformationExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeAssistanceInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type AssistanceInformationFailureListExtIETable struct{}

func AssistanceInformationFailureListExtIEs() AssistanceInformationFailureListExtIETable {
	return AssistanceInformationFailureListExtIETable{}
}
func (AssistanceInformationFailureListExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationFailureList-ExtIEs"}
		return sealed
	}()
}
func (t AssistanceInformationFailureListExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (AssistanceInformationFailureListExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationFailureListExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return AssistanceInformationFailureListExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationFailureListExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationFailureListExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return AssistanceInformationFailureListExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.AssistanceInformationFailureListExtIEsValue {
			sealed := q6.AssistanceInformationFailureListExtIEsValue{}
			*q6.BridgeAssistanceInformationFailureListExtIEsValueFieldId(&sealed) = id
			*q6.BridgeAssistanceInformationFailureListExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeAssistanceInformationFailureListExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type AssistanceInformationMetaDataExtIETable struct{}

func AssistanceInformationMetaDataExtIEs() AssistanceInformationMetaDataExtIETable {
	return AssistanceInformationMetaDataExtIETable{}
}
func (AssistanceInformationMetaDataExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationMetaData-ExtIEs"}
		return sealed
	}()
}
func (t AssistanceInformationMetaDataExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (AssistanceInformationMetaDataExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationMetaDataExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return AssistanceInformationMetaDataExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationMetaDataExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationMetaDataExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return AssistanceInformationMetaDataExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.AssistanceInformationMetaDataExtIEsValue {
			sealed := q6.AssistanceInformationMetaDataExtIEsValue{}
			*q6.BridgeAssistanceInformationMetaDataExtIEsValueFieldId(&sealed) = id
			*q6.BridgeAssistanceInformationMetaDataExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeAssistanceInformationMetaDataExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type CriticalityDiagnosticsExtIETable struct{}

func CriticalityDiagnosticsExtIEs() CriticalityDiagnosticsExtIETable {
	return CriticalityDiagnosticsExtIETable{}
}
func (CriticalityDiagnosticsExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-ExtIEs"}
		return sealed
	}()
}
func (t CriticalityDiagnosticsExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (CriticalityDiagnosticsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CriticalityDiagnosticsExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return CriticalityDiagnosticsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.CriticalityDiagnosticsExtIEsValue {
			sealed := q6.CriticalityDiagnosticsExtIEsValue{}
			*q6.BridgeCriticalityDiagnosticsExtIEsValueFieldId(&sealed) = id
			*q6.BridgeCriticalityDiagnosticsExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeCriticalityDiagnosticsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type CriticalityDiagnosticsIEListExtIETable struct{}

func CriticalityDiagnosticsIEListExtIEs() CriticalityDiagnosticsIEListExtIETable {
	return CriticalityDiagnosticsIEListExtIETable{}
}
func (CriticalityDiagnosticsIEListExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-IE-List-ExtIEs"}
		return sealed
	}()
}
func (t CriticalityDiagnosticsIEListExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (CriticalityDiagnosticsIEListExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CriticalityDiagnosticsIEListExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return CriticalityDiagnosticsIEListExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CriticalityDiagnosticsIEListExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return CriticalityDiagnosticsIEListExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return CriticalityDiagnosticsIEListExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.CriticalityDiagnosticsIEListExtIEsValue {
			sealed := q6.CriticalityDiagnosticsIEListExtIEsValue{}
			*q6.BridgeCriticalityDiagnosticsIEListExtIEsValueFieldId(&sealed) = id
			*q6.BridgeCriticalityDiagnosticsIEListExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeCriticalityDiagnosticsIEListExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ECGIExtIETable struct{}

func ECGIExtIEs() ECGIExtIETable { return ECGIExtIETable{} }
func (ECGIExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECGI-ExtIEs"}
		return sealed
	}()
}
func (t ECGIExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ECGIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECGIExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ECGIExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECGIExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECGIExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return ECGIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.ECGIExtIEsValue {
			sealed := q6.ECGIExtIEsValue{}
			*q6.BridgeECGIExtIEsValueFieldId(&sealed) = id
			*q6.BridgeECGIExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeECGIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type InterRATMeasurementQuantitiesValueExtIETable struct{}

func InterRATMeasurementQuantitiesValueExtIEs() InterRATMeasurementQuantitiesValueExtIETable {
	return InterRATMeasurementQuantitiesValueExtIETable{}
}
func (InterRATMeasurementQuantitiesValueExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantitiesValue-ExtIEs"}
		return sealed
	}()
}
func (t InterRATMeasurementQuantitiesValueExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (InterRATMeasurementQuantitiesValueExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InterRATMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return InterRATMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InterRATMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return InterRATMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return InterRATMeasurementQuantitiesValueExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.InterRATMeasurementQuantitiesValueExtIEsValue {
			sealed := q6.InterRATMeasurementQuantitiesValueExtIEsValue{}
			*q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldId(&sealed) = id
			*q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ECIDMeasurementTerminationCommandIETable struct{}

func ECIDMeasurementTerminationCommandIEs() ECIDMeasurementTerminationCommandIETable {
	return ECIDMeasurementTerminationCommandIETable{}
}
func (ECIDMeasurementTerminationCommandIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementTerminationCommandIETable) infoESMLCUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementTerminationCommandIEs().ID(), ID: q5.ProtocolIEID(2), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementTerminationCommandIETable) ESMLCUEMeasurementID() ECIDMeasurementTerminationCommandMeasurementIDIEBinding {
	return ECIDMeasurementTerminationCommandMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero q6.ECIDMeasurementTerminationCommandIEValue
			decoded, err := q6.BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(zero, q5.ProtocolIEID(2), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q7.Errorf("binding E-CIDMeasurementTerminationCommand-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return q6.BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh((func() q6.ECIDMeasurementTerminationCommandIEValue {
				sealed := q6.ECIDMeasurementTerminationCommandIEValue{}
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = q5.ProtocolIEID(2)
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q5.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q5.MeasurementID, options q4.DecodeState) (q5.MeasurementID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q5.MeasurementID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q6.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.MeasurementID) q6.ECIDMeasurementTerminationCommandIEValue {
			return func() q6.ECIDMeasurementTerminationCommandIEValue {
				sealed := q6.ECIDMeasurementTerminationCommandIEValue{}
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = q5.ProtocolIEID(2)
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q6.ECIDMeasurementTerminationCommandIEValue) (*q5.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementTerminationCommandIETable) infoENBUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementTerminationCommandIEs().ID(), ID: q5.ProtocolIEID(6), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementTerminationCommandIETable) ENBUEMeasurementID() ECIDMeasurementTerminationCommandMeasurementIDIEBinding {
	return ECIDMeasurementTerminationCommandMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero q6.ECIDMeasurementTerminationCommandIEValue
			decoded, err := q6.BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(zero, q5.ProtocolIEID(6), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q7.Errorf("binding E-CIDMeasurementTerminationCommand-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return q6.BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh((func() q6.ECIDMeasurementTerminationCommandIEValue {
				sealed := q6.ECIDMeasurementTerminationCommandIEValue{}
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = q5.ProtocolIEID(6)
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldRowENBUEMeasurementID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q5.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q5.MeasurementID, options q4.DecodeState) (q5.MeasurementID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q5.MeasurementID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q6.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.MeasurementID) q6.ECIDMeasurementTerminationCommandIEValue {
			return func() q6.ECIDMeasurementTerminationCommandIEValue {
				sealed := q6.ECIDMeasurementTerminationCommandIEValue{}
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = q5.ProtocolIEID(6)
				*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldRowENBUEMeasurementID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q6.ECIDMeasurementTerminationCommandIEValue) (*q5.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}
func (t ECIDMeasurementTerminationCommandIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ECIDMeasurementTerminationCommandIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(q7.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(2):
		return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(q7.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(6):
		return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(q7.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementTerminationCommandIEField{}, q4.OperationError(err, "Opaque")
		}
		return ECIDMeasurementTerminationCommandIEField{Id: id, Criticality: criticality, Value: func() q6.ECIDMeasurementTerminationCommandIEValue {
			sealed := q6.ECIDMeasurementTerminationCommandIEValue{}
			*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldId(&sealed) = id
			*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldOpaque(&sealed) = retained
			*q6.BridgeECIDMeasurementTerminationCommandIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

// RSSICodec binds the complete source value type.
func RSSICodec() q9.RSSIValueCodec {
	return func() q9.RSSIValueCodec {
		sealed := q9.RSSIValueCodec{}
		*q9.BridgeRSSIValueCodecFieldPath(&sealed) = "RSSI"
		*q9.BridgeRSSIValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.RSSI, error) {
			var zero q5.RSSI
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound19, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "RSSI"); err != nil {
				return zero, err
			}
			return q5.RSSI(decoded), nil
		}
		*q9.BridgeRSSIValueCodecFieldEncode(&sealed) = func(value q5.RSSI, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound19, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeRSSIValueCodecFieldCapture(&sealed) = func(v q5.RSSI, options q4.DecodeState) (q5.RSSI, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaRSSI(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeRSSIValueCodecFieldCompare(&sealed) = func(v q5.RSSI, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaRSSI(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*q9.BridgeRSSIValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:RSSI"
			return sealed
		}()
		return sealed
	}()

}

// RepetitionNumberofSIB1NBCodec binds the complete source value type.
func RepetitionNumberofSIB1NBCodec() q9.RepetitionNumberofSIB1NBValueCodec {
	return func() q9.RepetitionNumberofSIB1NBValueCodec {
		sealed := q9.RepetitionNumberofSIB1NBValueCodec{}
		*q9.BridgeRepetitionNumberofSIB1NBValueCodecFieldPath(&sealed) = "RepetitionNumberofSIB1NB"
		*q9.BridgeRepetitionNumberofSIB1NBValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.RepetitionNumberofSIB1NB, error) {
			var zero q5.RepetitionNumberofSIB1NB
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeEnumeratedAligned(bb, 3, true, q4.EnumerationSource{KnownExtensions: 0, Path: "RepetitionNumberofSIB1NB"})
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "RepetitionNumberofSIB1NB"); err != nil {
				return zero, err
			}
			return q5.RepetitionNumberofSIB1NB(decoded), nil
		}
		*q9.BridgeRepetitionNumberofSIB1NBValueCodecFieldEncode(&sealed) = func(value q5.RepetitionNumberofSIB1NB, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeEnumeratedAligned(bb, int64(value), 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeRepetitionNumberofSIB1NBValueCodecFieldCapture(&sealed) = func(v q5.RepetitionNumberofSIB1NB, options q4.DecodeState) (q5.RepetitionNumberofSIB1NB, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaRepetitionNumberofSIB1NB(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeRepetitionNumberofSIB1NBValueCodecFieldCompare(&sealed) = func(v q5.RepetitionNumberofSIB1NB, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaRepetitionNumberofSIB1NB(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*q9.BridgeRepetitionNumberofSIB1NBValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:RepetitionNumberofSIB1NB"
			return sealed
		}()
		return sealed
	}()

}

// SFNInitialisationTimeCodec binds the complete source value type.
func SFNInitialisationTimeCodec() q9.SFNInitialisationTimeValueCodec {
	return func() q9.SFNInitialisationTimeValueCodec {
		sealed := q9.SFNInitialisationTimeValueCodec{}
		*q9.BridgeSFNInitialisationTimeValueCodecFieldPath(&sealed) = "SFNInitialisationTime"
		*q9.BridgeSFNInitialisationTimeValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.SFNInitialisationTime, error) {
			var zero q5.SFNInitialisationTime
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			bits, length, err := q4.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "SFNInitialisationTime"); err != nil {
				return zero, err
			}
			return q5.SFNInitialisationTime(q8.BitString{Bytes: bits, BitLength: length}), nil
		}
		*q9.BridgeSFNInitialisationTimeValueCodecFieldEncode(&sealed) = func(value q5.SFNInitialisationTime, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeBitStringAligned(bb, value.Bytes, value.BitLength, 64, 64, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeSFNInitialisationTimeValueCodecFieldCapture(&sealed) = func(v q5.SFNInitialisationTime, options q4.DecodeState) (q5.SFNInitialisationTime, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaSFNInitialisationTime(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q9.BridgeSFNInitialisationTimeValueCodecFieldCompare(&sealed) = func(v q5.SFNInitialisationTime, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaSFNInitialisationTime(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeSFNInitialisationTimeValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:SFNInitialisationTime"
			return sealed
		}()
		return sealed
	}()

}

// SSIDCodec binds the complete source value type.
func SSIDCodec() q9.SSIDValueCodec {
	return func() q9.SSIDValueCodec {
		sealed := q9.SSIDValueCodec{}
		*q9.BridgeSSIDValueCodecFieldPath(&sealed) = "SSID"
		*q9.BridgeSSIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.SSID, error) {
			var zero q5.SSID
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := q4.DecodeOctetStringAligned(bb, 1, 32, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "SSID"); err != nil {
				return zero, err
			}
			return q5.SSID(octets), nil
		}
		*q9.BridgeSSIDValueCodecFieldEncode(&sealed) = func(value q5.SSID, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeOctetStringAligned(bb, []byte(value), 1, 32, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeSSIDValueCodecFieldCapture(&sealed) = func(v q5.SSID, options q4.DecodeState) (q5.SSID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaSSID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeSSIDValueCodecFieldCompare(&sealed) = func(v q5.SSID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaSSID(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*q9.BridgeSSIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:SSID"
			return sealed
		}()
		return sealed
	}()

}

// TACCodec binds the complete source value type.
func TACCodec() q9.TACValueCodec {
	return func() q9.TACValueCodec {
		sealed := q9.TACValueCodec{}
		*q9.BridgeTACValueCodecFieldPath(&sealed) = "TAC"
		*q9.BridgeTACValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.TAC, error) {
			var zero q5.TAC
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := q4.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "TAC"); err != nil {
				return zero, err
			}
			return q5.TAC(octets), nil
		}
		*q9.BridgeTACValueCodecFieldEncode(&sealed) = func(value q5.TAC, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeOctetStringAligned(bb, []byte(value), 2, 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeTACValueCodecFieldCapture(&sealed) = func(v q5.TAC, options q4.DecodeState) (q5.TAC, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaTAC(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeTACValueCodecFieldCompare(&sealed) = func(v q5.TAC, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaTAC(&v, &s)
			s.End(f, root,
				false)
			return s.Plan()
		}
		*q9.BridgeTACValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:TAC"
			return sealed
		}()
		return sealed
	}()

}

// TPIDCodec binds the complete source value type.
func TPIDCodec() q9.TPIDValueCodec {
	return func() q9.TPIDValueCodec {
		sealed := q9.TPIDValueCodec{}
		*q9.BridgeTPIDValueCodecFieldPath(&sealed) = "TPID"
		*q9.BridgeTPIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.TPID, error) {
			var zero q5.TPID
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "TPID"); err != nil {
				return zero, err
			}
			return q5.TPID(decoded), nil
		}
		*q9.BridgeTPIDValueCodecFieldEncode(&sealed) = func(value q5.TPID, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound14, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeTPIDValueCodecFieldCapture(&sealed) = func(v q5.TPID, options q4.DecodeState) (q5.TPID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaTPID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeTPIDValueCodecFieldCompare(&sealed) = func(v q5.TPID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaTPID(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*q9.BridgeTPIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:TPID"
			return sealed
		}()
		return sealed
	}()

}

// TPTypeCodec binds the complete source value type.
func TPTypeCodec() q9.TPTypeValueCodec {
	return func() q9.TPTypeValueCodec {
		sealed := q9.TPTypeValueCodec{}
		*q9.BridgeTPTypeValueCodecFieldPath(&sealed) = "TPType"
		*q9.BridgeTPTypeValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.TPType, error) {
			var zero q5.TPType
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeEnumeratedAligned(bb, 1, true, q4.EnumerationSource{KnownExtensions: 0, Path: "TPType"})
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "TPType"); err != nil {
				return zero, err
			}
			return q5.TPType(decoded), nil
		}
		*q9.BridgeTPTypeValueCodecFieldEncode(&sealed) = func(value q5.TPType, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeTPTypeValueCodecFieldCapture(&sealed) = func(v q5.TPType, options q4.DecodeState) (q5.TPType, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.
				Begin()
			q5.BridgeCaptureLPPaTPType(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeTPTypeValueCodecFieldCompare(&sealed) = func(v q5.TPType, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaTPType(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeTPTypeValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:TPType"
			return sealed
		}()
		return sealed
	}()

}

// TriggeringMessageCodec binds the complete source value type.
func TriggeringMessageCodec() q9.TriggeringMessageValueCodec {
	return func() q9.TriggeringMessageValueCodec {
		sealed := q9.TriggeringMessageValueCodec{}
		*q9.BridgeTriggeringMessageValueCodecFieldPath(&sealed) = "TriggeringMessage"
		*q9.BridgeTriggeringMessageValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.TriggeringMessage, error) {
			var zero q5.TriggeringMessage
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeEnumeratedAligned(bb, 3, false, q4.EnumerationSource{KnownExtensions: 0, Path: "TriggeringMessage"})
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "TriggeringMessage"); err != nil {
				return zero, err
			}
			return q5.TriggeringMessage(decoded), nil
		}
		*q9.BridgeTriggeringMessageValueCodecFieldEncode(&sealed) = func(value q5.TriggeringMessage, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeEnumeratedAligned(bb, int64(value), 3, false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeTriggeringMessageValueCodecFieldCapture(&sealed) = func(v q5.TriggeringMessage, options q4.DecodeState) (q5.TriggeringMessage, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaTriggeringMessage(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*q9.BridgeTriggeringMessageValueCodecFieldCompare(&sealed) = func(v q5.TriggeringMessage, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaTriggeringMessage(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeTriggeringMessageValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:TriggeringMessage"
			return sealed
		}()
		return sealed
	}()

}

// TypeOfErrorCodec binds the complete source value type.
func TypeOfErrorCodec() q9.TypeOfErrorValueCodec {
	return func() q9.TypeOfErrorValueCodec {
		sealed := q9.TypeOfErrorValueCodec{}
		*q9.BridgeTypeOfErrorValueCodecFieldPath(&sealed) = "TypeOfError"
		*q9.BridgeTypeOfErrorValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.TypeOfError, error) {
			var zero q5.TypeOfError
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeEnumeratedAligned(bb, 2, true, q4.EnumerationSource{KnownExtensions: 0, Path: "TypeOfError"})
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "TypeOfError"); err != nil {
				return zero, err
			}
			return q5.TypeOfError(decoded), nil
		}
		*q9.BridgeTypeOfErrorValueCodecFieldEncode(&sealed) = func(value q5.TypeOfError, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeTypeOfErrorValueCodecFieldCapture(&sealed) = func(v q5.TypeOfError, options q4.DecodeState) (q5.TypeOfError, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaTypeOfError(&v, &s)
			var root q4.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*q9.BridgeTypeOfErrorValueCodecFieldCompare(&sealed) = func(v q5.TypeOfError, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaTypeOfError(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeTypeOfErrorValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:TypeOfError"
			return sealed
		}()
		return sealed
	}()

}

// UARFCNCodec binds the complete source value type.
func UARFCNCodec() q9.UARFCNValueCodec {
	return func() q9.UARFCNValueCodec {
		sealed := q9.UARFCNValueCodec{}
		*q9.BridgeUARFCNValueCodecFieldPath(&sealed) = "UARFCN"
		*q9.BridgeUARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.UARFCN, error) {
			var zero q5.UARFCN
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound10, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "UARFCN"); err != nil {
				return zero, err
			}
			return q5.UARFCN(decoded), nil
		}
		*q9.BridgeUARFCNValueCodecFieldEncode(&sealed) = func(value q5.UARFCN, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound10, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeUARFCNValueCodecFieldCapture(&sealed) = func(v q5.UARFCN, options q4.DecodeState) (q5.UARFCN, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.
				Begin()
			q5.BridgeCaptureLPPaUARFCN(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeUARFCNValueCodecFieldCompare(&sealed) = func(v q5.UARFCN, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaUARFCN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeUARFCNValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:UARFCN"
			return sealed
		}()
		return sealed
	}()

}

// UTRAEcN0Codec binds the complete source value type.
func UTRAEcN0Codec() q9.UTRAEcN0ValueCodec {
	return func() q9.UTRAEcN0ValueCodec {
		sealed := q9.UTRAEcN0ValueCodec{}
		*q9.BridgeUTRAEcN0ValueCodecFieldPath(&sealed) = "UTRAEcN0"
		*q9.BridgeUTRAEcN0ValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.UTRAEcN0, error) {
			var zero q5.UTRAEcN0
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound15, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "UTRAEcN0"); err != nil {
				return zero, err
			}
			return q5.UTRAEcN0(decoded), nil
		}
		*q9.BridgeUTRAEcN0ValueCodecFieldEncode(&sealed) = func(value q5.UTRAEcN0, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound15, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeUTRAEcN0ValueCodecFieldCapture(&sealed) = func(v q5.UTRAEcN0, options q4.DecodeState) (q5.UTRAEcN0, q4.Snapshot) {
			s := q4.SemanticCaptureFor(
				options)
			f := s.Begin()
			q5.BridgeCaptureLPPaUTRAEcN0(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeUTRAEcN0ValueCodecFieldCompare(&sealed) = func(v q5.UTRAEcN0, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaUTRAEcN0(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeUTRAEcN0ValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:UTRAEcN0"
			return sealed
		}()
		return sealed
	}()

}

// UTRARSCPCodec binds the complete source value type.
func UTRARSCPCodec() q9.UTRARSCPValueCodec {
	return func() q9.UTRARSCPValueCodec {
		sealed := q9.UTRARSCPValueCodec{}
		*q9.BridgeUTRARSCPValueCodecFieldPath(&sealed) = "UTRARSCP"
		*q9.BridgeUTRARSCPValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.UTRARSCP, error) {
			var zero q5.UTRARSCP
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound0, q5.BridgeAsn1IntegerBound21, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "UTRARSCP"); err != nil {
				return zero, err
			}
			return q5.UTRARSCP(decoded), nil
		}
		*q9.BridgeUTRARSCPValueCodecFieldEncode(&sealed) = func(value q5.UTRARSCP, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound0, q5.BridgeAsn1IntegerBound21, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeUTRARSCPValueCodecFieldCapture(&sealed) = func(v q5.UTRARSCP, options q4.DecodeState) (q5.UTRARSCP, q4.Snapshot) {
			s := q4.SemanticCaptureFor(
				options)
			f := s.Begin()
			q5.BridgeCaptureLPPaUTRARSCP(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeUTRARSCPValueCodecFieldCompare(&sealed) = func(v q5.UTRARSCP, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaUTRARSCP(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeUTRARSCPValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:UTRARSCP"
			return sealed
		}()
		return sealed
	}()

}

// ValueRSRPCodec binds the complete source value type.
func ValueRSRPCodec() q9.ValueRSRPValueCodec {
	return func() q9.ValueRSRPValueCodec {
		sealed := q9.ValueRSRPValueCodec{}
		*q9.BridgeValueRSRPValueCodecFieldPath(&sealed) = "ValueRSRP"
		*q9.BridgeValueRSRPValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.ValueRSRP, error) {
			var zero q5.ValueRSRP
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound22, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "ValueRSRP"); err != nil {
				return zero, err
			}
			return q5.ValueRSRP(decoded), nil
		}
		*q9.BridgeValueRSRPValueCodecFieldEncode(&sealed) = func(value q5.ValueRSRP, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound22, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeValueRSRPValueCodecFieldCapture(&sealed) = func(v q5.ValueRSRP, options q4.DecodeState) (q5.ValueRSRP, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.
				Begin()
			q5.BridgeCaptureLPPaValueRSRP(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeValueRSRPValueCodecFieldCompare(&sealed) = func(v q5.ValueRSRP, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaValueRSRP(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeValueRSRPValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ValueRSRP"
			return sealed
		}()
		return sealed
	}()

}

// ValueRSRQCodec binds the complete source value type.
func ValueRSRQCodec() q9.ValueRSRQValueCodec {
	return func() q9.ValueRSRQValueCodec {
		sealed := q9.ValueRSRQValueCodec{}
		*q9.BridgeValueRSRQValueCodecFieldPath(&sealed) = "ValueRSRQ"
		*q9.BridgeValueRSRQValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.ValueRSRQ, error) {
			var zero q5.ValueRSRQ
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound13, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "ValueRSRQ"); err != nil {
				return zero, err
			}
			return q5.ValueRSRQ(decoded), nil
		}
		*q9.BridgeValueRSRQValueCodecFieldEncode(&sealed) = func(value q5.ValueRSRQ, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound13, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeValueRSRQValueCodecFieldCapture(&sealed) = func(v q5.ValueRSRQ, options q4.DecodeState) (q5.ValueRSRQ, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.
				Begin()
			q5.BridgeCaptureLPPaValueRSRQ(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeValueRSRQValueCodecFieldCompare(&sealed) = func(v q5.ValueRSRQ, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaValueRSRQ(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeValueRSRQValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ValueRSRQ"
			return sealed
		}()
		return sealed
	}()

}

// WLANBandCodec binds the complete source value type.
func WLANBandCodec() q9.WLANBandValueCodec {
	return func() q9.WLANBandValueCodec {
		sealed := q9.WLANBandValueCodec{}
		*q9.BridgeWLANBandValueCodecFieldPath(&sealed) = "WLANBand"
		*q9.BridgeWLANBandValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.WLANBand, error) {
			var zero q5.WLANBand
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeEnumeratedAligned(bb, 2, true, q4.EnumerationSource{KnownExtensions: 0, Path: "WLANBand"})
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "WLANBand"); err != nil {
				return zero, err
			}
			return q5.WLANBand(decoded), nil
		}
		*q9.BridgeWLANBandValueCodecFieldEncode(&sealed) = func(value q5.WLANBand, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q9.BridgeWLANBandValueCodecFieldCapture(&sealed) = func(v q5.WLANBand, options q4.DecodeState) (q5.WLANBand, q4.Snapshot) {
			s := q4.SemanticCaptureFor(
				options)
			f := s.Begin()
			q5.BridgeCaptureLPPaWLANBand(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeWLANBandValueCodecFieldCompare(&sealed) = func(v q5.WLANBand, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANBand(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeWLANBandValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANBand"
			return sealed
		}()
		return sealed
	}()

}

// WLANCountryCodeCodec binds the complete source value type.
func WLANCountryCodeCodec() q6.WLANCountryCodeValueCodec {
	return func() q6.WLANCountryCodeValueCodec {
		sealed := q6.WLANCountryCodeValueCodec{}
		*q6.BridgeWLANCountryCodeValueCodecFieldPath(&sealed) = "WLANCountryCode"
		*q6.BridgeWLANCountryCodeValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.WLANCountryCode, error) {
			var zero q5.WLANCountryCode
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeEnumeratedAligned(bb, 4, true, q4.EnumerationSource{KnownExtensions: 0, Path: "WLANCountryCode"})
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "WLANCountryCode"); err != nil {
				return zero, err
			}
			return q5.WLANCountryCode(decoded), nil
		}
		*q6.BridgeWLANCountryCodeValueCodecFieldEncode(&sealed) = func(value q5.WLANCountryCode, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeEnumeratedAligned(bb, int64(value), 4, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeWLANCountryCodeValueCodecFieldCapture(&sealed) = func(v q5.WLANCountryCode, options q4.DecodeState) (q5.WLANCountryCode, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaWLANCountryCode(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgeWLANCountryCodeValueCodecFieldCompare(&sealed) = func(v q5.WLANCountryCode, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANCountryCode(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgeWLANCountryCodeValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANCountryCode"
			return sealed
		}()
		return sealed
	}()

}

// WLANMeasurementQuantitiesValueCodec binds the complete source value type.
func WLANMeasurementQuantitiesValueCodec() q6.WLANMeasurementQuantitiesValueValueCodec {
	return func() q6.WLANMeasurementQuantitiesValueValueCodec {
		sealed := q6.WLANMeasurementQuantitiesValueValueCodec{}
		*q6.BridgeWLANMeasurementQuantitiesValueValueCodecFieldPath(&sealed) = "WLANMeasurementQuantitiesValue"
		*q6.BridgeWLANMeasurementQuantitiesValueValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.WLANMeasurementQuantitiesValue, error) {
			var zero q5.WLANMeasurementQuantitiesValue
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeEnumeratedAligned(bb, 1, true, q4.EnumerationSource{KnownExtensions: 0, Path: "WLANMeasurementQuantitiesValue"})
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "WLANMeasurementQuantitiesValue"); err != nil {
				return zero, err
			}
			return q5.WLANMeasurementQuantitiesValue(decoded), nil
		}
		*q6.BridgeWLANMeasurementQuantitiesValueValueCodecFieldEncode(&sealed) = func(value q5.WLANMeasurementQuantitiesValue, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeWLANMeasurementQuantitiesValueValueCodecFieldCapture(&sealed) = func(v q5.WLANMeasurementQuantitiesValue, options q4.DecodeState) (q5.WLANMeasurementQuantitiesValue, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaWLANMeasurementQuantitiesValue(&v, &s)
			var root q4.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgeWLANMeasurementQuantitiesValueValueCodecFieldCompare(&sealed) = func(v q5.WLANMeasurementQuantitiesValue, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANMeasurementQuantitiesValue(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgeWLANMeasurementQuantitiesValueValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementQuantitiesValue"
			return sealed
		}()
		return sealed
	}()

}

// WLANRSSICodec binds the complete source value type.
func WLANRSSICodec() q6.WLANRSSIValueCodec {
	return func() q6.WLANRSSIValueCodec {
		sealed := q6.WLANRSSIValueCodec{}
		*q6.BridgeWLANRSSIValueCodecFieldPath(&sealed) = "WLANRSSI"
		*q6.BridgeWLANRSSIValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.WLANRSSI, error) {
			var zero q5.WLANRSSI
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound6, true)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "WLANRSSI"); err != nil {
				return zero, err
			}
			return q5.WLANRSSI(decoded), nil
		}
		*q6.BridgeWLANRSSIValueCodecFieldEncode(&sealed) = func(value q5.WLANRSSI, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerBigBoundsAligned(bb, value, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeWLANRSSIValueCodecFieldCapture(&sealed) = func(v q5.WLANRSSI, options q4.DecodeState) (q5.WLANRSSI, q4.Snapshot) {
			s := q4.SemanticCaptureFor(
				options)
			f := s.Begin()
			q5.BridgeCaptureLPPaWLANRSSI(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgeWLANRSSIValueCodecFieldCompare(&sealed) = func(v q5.WLANRSSI, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANRSSI(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgeWLANRSSIValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANRSSI"
			return sealed
		}()
		return sealed
	}()

}
func BridgeAddOTDOACellsExtIEsExtFieldFieldReceived(v *AddOTDOACellsExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeAddOTDOACellsExtIEsExtFieldFieldReplay(v *AddOTDOACellsExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsExtIEsExtFieldFieldStream(v *AddOTDOACellsExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeAddOTDOACellsExtIEsExtFieldFieldWithoutReplay(v *AddOTDOACellsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(v *AddOTDOACellsExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAddOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(v *AddOTDOACellsExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldReceived(v *AddOTDOACellsExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldReplay(v *AddOTDOACellsExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldStream(v *AddOTDOACellsExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeAddOTDOACellsExtIEsIEFieldFieldWithoutReplay(v *AddOTDOACellsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsExtIEsIEFieldMethodMarshalAPERTo(v *AddOTDOACellsExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAddOTDOACellsExtIEsIEFieldMethodUnmarshalAPERFrom(v *AddOTDOACellsExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationExtIEsExtFieldFieldReceived(v *AssistanceInformationExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationExtIEsExtFieldFieldReplay(v *AssistanceInformationExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationExtIEsExtFieldFieldStream(v *AssistanceInformationExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v *AssistanceInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceInformationExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceInformationExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationExtIEsIEFieldFieldReceived(v *AssistanceInformationExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationExtIEsIEFieldFieldReplay(v *AssistanceInformationExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationExtIEsIEFieldFieldStream(v *AssistanceInformationExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationExtIEsIEFieldFieldWithoutReplay(v *AssistanceInformationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationExtIEsIEFieldMethodMarshalAPERTo(v *AssistanceInformationExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationExtIEsIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReceived(v *AssistanceInformationFailureListExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReplay(v *AssistanceInformationFailureListExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldStream(v *AssistanceInformationFailureListExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldFieldWithoutReplay(v *AssistanceInformationFailureListExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceInformationFailureListExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFailureListExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceInformationFailureListExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldReceived(v *AssistanceInformationFailureListExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldReplay(v *AssistanceInformationFailureListExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldStream(v *AssistanceInformationFailureListExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldFieldWithoutReplay(v *AssistanceInformationFailureListExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldMethodMarshalAPERTo(v *AssistanceInformationFailureListExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFailureListExtIEsIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationFailureListExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReceived(v *AssistanceInformationMetaDataExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReplay(v *AssistanceInformationMetaDataExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldStream(v *AssistanceInformationMetaDataExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldWithoutReplay(v *AssistanceInformationMetaDataExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceInformationMetaDataExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceInformationMetaDataExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldReceived(v *AssistanceInformationMetaDataExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldReplay(v *AssistanceInformationMetaDataExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldStream(v *AssistanceInformationMetaDataExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldFieldWithoutReplay(v *AssistanceInformationMetaDataExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldMethodMarshalAPERTo(v *AssistanceInformationMetaDataExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMetaDataExtIEsIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationMetaDataExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReceived(v *CriticalityDiagnosticsExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v *CriticalityDiagnosticsExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldStream(v *CriticalityDiagnosticsExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v *CriticalityDiagnosticsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldReceived(v *CriticalityDiagnosticsExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldReplay(v *CriticalityDiagnosticsExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldStream(v *CriticalityDiagnosticsExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldFieldWithoutReplay(v *CriticalityDiagnosticsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsExtIEsIEFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReceived(v *CriticalityDiagnosticsIEListExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReplay(v *CriticalityDiagnosticsIEListExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldStream(v *CriticalityDiagnosticsIEListExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldWithoutReplay(v *CriticalityDiagnosticsIEListExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsIEListExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEListExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldReceived(v *CriticalityDiagnosticsIEListExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldReplay(v *CriticalityDiagnosticsIEListExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldStream(v *CriticalityDiagnosticsIEListExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldFieldWithoutReplay(v *CriticalityDiagnosticsIEListExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsIEListExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEListExtIEsIEFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEListExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECGIExtIEsExtFieldFieldReceived(v *ECGIExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeECGIExtIEsExtFieldFieldReplay(v *ECGIExtIEsExtField) *q4.Snapshot { return &v.replay }
func BridgeECGIExtIEsExtFieldFieldStream(v *ECGIExtIEsExtField) *q4.WireSpan { return &v.stream }
func BridgeECGIExtIEsExtFieldFieldWithoutReplay(v *ECGIExtIEsExtField) *bool { return &v.withoutReplay }
func BridgeECGIExtIEsExtFieldMethodMarshalAPERTo(v *ECGIExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECGIExtIEsExtFieldMethodUnmarshalAPERFrom(v *ECGIExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECGIExtIEsIEFieldFieldReceived(v *ECGIExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeECGIExtIEsIEFieldFieldReplay(v *ECGIExtIEsIEField) *q4.Snapshot { return &v.replay }
func BridgeECGIExtIEsIEFieldFieldStream(v *ECGIExtIEsIEField) *q4.WireSpan { return &v.stream }
func BridgeECGIExtIEsIEFieldFieldWithoutReplay(v *ECGIExtIEsIEField) *bool { return &v.withoutReplay }
func BridgeECGIExtIEsIEFieldMethodMarshalAPERTo(v *ECGIExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECGIExtIEsIEFieldMethodUnmarshalAPERFrom(v *ECGIExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldReceived(v *ECIDMeasurementTerminationCommandIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldReplay(v *ECIDMeasurementTerminationCommandIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldStream(v *ECIDMeasurementTerminationCommandIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementTerminationCommandIEFieldFieldWithoutReplay(v *ECIDMeasurementTerminationCommandIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementTerminationCommandIEFieldMethodMarshalAPERTo(v *ECIDMeasurementTerminationCommandIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementTerminationCommandIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementTerminationCommandIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementTerminationCommandIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementTerminationCommandIETable) q5.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementTerminationCommandIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementTerminationCommandIETable) q5.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *q5.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldGet(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *func(*q6.ECIDMeasurementTerminationCommandIEValue) (*q5.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementTerminationCommandMeasurementIDIEBindingFieldInject(v *ECIDMeasurementTerminationCommandMeasurementIDIEBinding) *func(q5.MeasurementID) q6.ECIDMeasurementTerminationCommandIEValue {
	return &v.inject
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReceived(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v *InterRATMeasurementQuantitiesValueExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(v *InterRATMeasurementQuantitiesValueExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(v *InterRATMeasurementQuantitiesValueExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsIEFieldFieldReceived(v *InterRATMeasurementQuantitiesValueExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsIEFieldFieldReplay(v *InterRATMeasurementQuantitiesValueExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsIEFieldFieldStream(v *InterRATMeasurementQuantitiesValueExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsIEFieldFieldWithoutReplay(v *InterRATMeasurementQuantitiesValueExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsIEFieldMethodMarshalAPERTo(v *InterRATMeasurementQuantitiesValueExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsIEFieldMethodUnmarshalAPERFrom(v *InterRATMeasurementQuantitiesValueExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsExtIEsValueFieldId(v *PosSIBsExtIEsValue) *q5.ProtocolIEID        { return &v.id }
func BridgePosSIBsExtIEsValueFieldIsOpaque(v *PosSIBsExtIEsValue) *bool             { return &v.isOpaque }
func BridgePosSIBsExtIEsValueFieldOpaque(v *PosSIBsExtIEsValue) **q4.OpaqueOpenType { return &v.opaque }
func BridgePosSIBsExtIEsValueFieldReceived(v *PosSIBsExtIEsValue) *q4.WireSpan      { return &v.received }
func BridgePosSIBsExtIEsValueFieldReplay(v *PosSIBsExtIEsValue) *q4.Snapshot        { return &v.replay }
func BridgePosSIBsExtIEsValueFieldWithoutReplay(v *PosSIBsExtIEsValue) *bool        { return &v.withoutReplay }
func BridgePosSIBsExtIEsValueMethodCaptureFraming(v PosSIBsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePosSIBsExtIEsValueMethodCaptureSemantics(v PosSIBsExtIEsValue, a0 q4.SemanticCapture) PosSIBsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgePosSIBsExtIEsValueMethodCaptureSnapshot(v PosSIBsExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgePosSIBsExtIEsValueMethodCompareSemantics(v PosSIBsExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePosSIBsExtIEsValueMethodDecode(v PosSIBsExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (PosSIBsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePosSIBsExtIEsValueMethodEncode(v PosSIBsExtIEsValue) ([]byte, error) { return v.encode() }
func BridgePosSIBsExtIEsValueMethodEncodeFresh(v PosSIBsExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePosSIBsExtIEsValueMethodMatchesID(v PosSIBsExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePosSIBsExtIEsValueMethodReason(v PosSIBsExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgePosSIBsExtIEsValueMethodRule(v PosSIBsExtIEsValue) q4.SourceRule { return v.rule() }
func BridgeResultGERANItemExtIEsValueFieldId(v *ResultGERANItemExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeResultGERANItemExtIEsValueFieldIsOpaque(v *ResultGERANItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultGERANItemExtIEsValueFieldOpaque(v *ResultGERANItemExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultGERANItemExtIEsValueFieldReceived(v *ResultGERANItemExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultGERANItemExtIEsValueFieldReplay(v *ResultGERANItemExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemExtIEsValueFieldWithoutReplay(v *ResultGERANItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemExtIEsValueMethodCaptureFraming(v ResultGERANItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultGERANItemExtIEsValueMethodCaptureSemantics(v ResultGERANItemExtIEsValue, a0 q4.SemanticCapture) ResultGERANItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultGERANItemExtIEsValueMethodCaptureSnapshot(v ResultGERANItemExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultGERANItemExtIEsValueMethodCompareSemantics(v ResultGERANItemExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultGERANItemExtIEsValueMethodDecode(v ResultGERANItemExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ResultGERANItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultGERANItemExtIEsValueMethodEncode(v ResultGERANItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultGERANItemExtIEsValueMethodEncodeFresh(v ResultGERANItemExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultGERANItemExtIEsValueMethodMatchesID(v ResultGERANItemExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultGERANItemExtIEsValueMethodReason(v ResultGERANItemExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultGERANItemExtIEsValueMethodRule(v ResultGERANItemExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeResultRSRPItemExtIEsValueFieldId(v *ResultRSRPItemExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeResultRSRPItemExtIEsValueFieldIsOpaque(v *ResultRSRPItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultRSRPItemExtIEsValueFieldOpaque(v *ResultRSRPItemExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultRSRPItemExtIEsValueFieldReceived(v *ResultRSRPItemExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultRSRPItemExtIEsValueFieldReplay(v *ResultRSRPItemExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemExtIEsValueFieldWithoutReplay(v *ResultRSRPItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemExtIEsValueMethodCaptureFraming(v ResultRSRPItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultRSRPItemExtIEsValueMethodCaptureSemantics(v ResultRSRPItemExtIEsValue, a0 q4.SemanticCapture) ResultRSRPItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultRSRPItemExtIEsValueMethodCaptureSnapshot(v ResultRSRPItemExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultRSRPItemExtIEsValueMethodCompareSemantics(v ResultRSRPItemExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultRSRPItemExtIEsValueMethodDecode(v ResultRSRPItemExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ResultRSRPItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultRSRPItemExtIEsValueMethodEncode(v ResultRSRPItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultRSRPItemExtIEsValueMethodEncodeFresh(v ResultRSRPItemExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultRSRPItemExtIEsValueMethodMatchesID(v ResultRSRPItemExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultRSRPItemExtIEsValueMethodReason(v ResultRSRPItemExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultRSRPItemExtIEsValueMethodRule(v ResultRSRPItemExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeResultRSRQItemExtIEsValueFieldId(v *ResultRSRQItemExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeResultRSRQItemExtIEsValueFieldIsOpaque(v *ResultRSRQItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultRSRQItemExtIEsValueFieldOpaque(v *ResultRSRQItemExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultRSRQItemExtIEsValueFieldReceived(v *ResultRSRQItemExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultRSRQItemExtIEsValueFieldReplay(v *ResultRSRQItemExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemExtIEsValueFieldWithoutReplay(v *ResultRSRQItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemExtIEsValueMethodCaptureFraming(v ResultRSRQItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultRSRQItemExtIEsValueMethodCaptureSemantics(v ResultRSRQItemExtIEsValue, a0 q4.SemanticCapture) ResultRSRQItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultRSRQItemExtIEsValueMethodCaptureSnapshot(v ResultRSRQItemExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultRSRQItemExtIEsValueMethodCompareSemantics(v ResultRSRQItemExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultRSRQItemExtIEsValueMethodDecode(v ResultRSRQItemExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ResultRSRQItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultRSRQItemExtIEsValueMethodEncode(v ResultRSRQItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultRSRQItemExtIEsValueMethodEncodeFresh(v ResultRSRQItemExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultRSRQItemExtIEsValueMethodMatchesID(v ResultRSRQItemExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultRSRQItemExtIEsValueMethodReason(v ResultRSRQItemExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultRSRQItemExtIEsValueMethodRule(v ResultRSRQItemExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeResultUTRANItemExtIEsValueFieldId(v *ResultUTRANItemExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeResultUTRANItemExtIEsValueFieldIsOpaque(v *ResultUTRANItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultUTRANItemExtIEsValueFieldOpaque(v *ResultUTRANItemExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultUTRANItemExtIEsValueFieldReceived(v *ResultUTRANItemExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultUTRANItemExtIEsValueFieldReplay(v *ResultUTRANItemExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemExtIEsValueFieldWithoutReplay(v *ResultUTRANItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemExtIEsValueMethodCaptureFraming(v ResultUTRANItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultUTRANItemExtIEsValueMethodCaptureSemantics(v ResultUTRANItemExtIEsValue, a0 q4.SemanticCapture) ResultUTRANItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultUTRANItemExtIEsValueMethodCaptureSnapshot(v ResultUTRANItemExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultUTRANItemExtIEsValueMethodCompareSemantics(v ResultUTRANItemExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultUTRANItemExtIEsValueMethodDecode(v ResultUTRANItemExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ResultUTRANItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultUTRANItemExtIEsValueMethodEncode(v ResultUTRANItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultUTRANItemExtIEsValueMethodEncodeFresh(v ResultUTRANItemExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultUTRANItemExtIEsValueMethodMatchesID(v ResultUTRANItemExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultUTRANItemExtIEsValueMethodReason(v ResultUTRANItemExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultUTRANItemExtIEsValueMethodRule(v ResultUTRANItemExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldId(v *ResultsPerSSBIndexItemExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldIsOpaque(v *ResultsPerSSBIndexItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldOpaque(v *ResultsPerSSBIndexItemExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldReceived(v *ResultsPerSSBIndexItemExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldReplay(v *ResultsPerSSBIndexItemExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemExtIEsValueFieldWithoutReplay(v *ResultsPerSSBIndexItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureFraming(v ResultsPerSSBIndexItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSemantics(v ResultsPerSSBIndexItemExtIEsValue, a0 q4.SemanticCapture) ResultsPerSSBIndexItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSnapshot(v ResultsPerSSBIndexItemExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodCompareSemantics(v ResultsPerSSBIndexItemExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodDecode(v ResultsPerSSBIndexItemExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ResultsPerSSBIndexItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodEncode(v ResultsPerSSBIndexItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodEncodeFresh(v ResultsPerSSBIndexItemExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(v ResultsPerSSBIndexItemExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodReason(v ResultsPerSSBIndexItemExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(v ResultsPerSSBIndexItemExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeSystemInformationExtIEsValueFieldId(v *SystemInformationExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeSystemInformationExtIEsValueFieldIsOpaque(v *SystemInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeSystemInformationExtIEsValueFieldOpaque(v *SystemInformationExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeSystemInformationExtIEsValueFieldReceived(v *SystemInformationExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeSystemInformationExtIEsValueFieldReplay(v *SystemInformationExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeSystemInformationExtIEsValueFieldWithoutReplay(v *SystemInformationExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationExtIEsValueMethodCaptureFraming(v SystemInformationExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeSystemInformationExtIEsValueMethodCaptureSemantics(v SystemInformationExtIEsValue, a0 q4.SemanticCapture) SystemInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeSystemInformationExtIEsValueMethodCaptureSnapshot(v SystemInformationExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeSystemInformationExtIEsValueMethodCompareSemantics(v SystemInformationExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSystemInformationExtIEsValueMethodDecode(v SystemInformationExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (SystemInformationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeSystemInformationExtIEsValueMethodEncode(v SystemInformationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeSystemInformationExtIEsValueMethodEncodeFresh(v SystemInformationExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSystemInformationExtIEsValueMethodMatchesID(v SystemInformationExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeSystemInformationExtIEsValueMethodReason(v SystemInformationExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeSystemInformationExtIEsValueMethodRule(v SystemInformationExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeTDDConfigurationExtIEsValueFieldId(v *TDDConfigurationExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeTDDConfigurationExtIEsValueFieldIsOpaque(v *TDDConfigurationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeTDDConfigurationExtIEsValueFieldOpaque(v *TDDConfigurationExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeTDDConfigurationExtIEsValueFieldReceived(v *TDDConfigurationExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeTDDConfigurationExtIEsValueFieldReplay(v *TDDConfigurationExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationExtIEsValueFieldWithoutReplay(v *TDDConfigurationExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationExtIEsValueMethodCaptureFraming(v TDDConfigurationExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeTDDConfigurationExtIEsValueMethodCaptureSemantics(v TDDConfigurationExtIEsValue, a0 q4.SemanticCapture) TDDConfigurationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeTDDConfigurationExtIEsValueMethodCaptureSnapshot(v TDDConfigurationExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeTDDConfigurationExtIEsValueMethodCompareSemantics(v TDDConfigurationExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeTDDConfigurationExtIEsValueMethodDecode(v TDDConfigurationExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (TDDConfigurationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeTDDConfigurationExtIEsValueMethodEncode(v TDDConfigurationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeTDDConfigurationExtIEsValueMethodEncodeFresh(v TDDConfigurationExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeTDDConfigurationExtIEsValueMethodMatchesID(v TDDConfigurationExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeTDDConfigurationExtIEsValueMethodReason(v TDDConfigurationExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeTDDConfigurationExtIEsValueMethodRule(v TDDConfigurationExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldId(v *WLANMeasurementQuantitiesValueExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(v *WLANMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldOpaque(v *WLANMeasurementQuantitiesValueExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldReceived(v *WLANMeasurementQuantitiesValueExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldReplay(v *WLANMeasurementQuantitiesValueExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldWithoutReplay(v *WLANMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v WLANMeasurementQuantitiesValueExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v WLANMeasurementQuantitiesValueExtIEsValue, a0 q4.SemanticCapture) WLANMeasurementQuantitiesValueExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v WLANMeasurementQuantitiesValueExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v WLANMeasurementQuantitiesValueExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodDecode(v WLANMeasurementQuantitiesValueExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (WLANMeasurementQuantitiesValueExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncode(v WLANMeasurementQuantitiesValueExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v WLANMeasurementQuantitiesValueExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v WLANMeasurementQuantitiesValueExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodReason(v WLANMeasurementQuantitiesValueExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodRule(v WLANMeasurementQuantitiesValueExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldId(v *WLANMeasurementResultItemExtIEsValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldIsOpaque(v *WLANMeasurementResultItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldOpaque(v *WLANMeasurementResultItemExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldReceived(v *WLANMeasurementResultItemExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldReplay(v *WLANMeasurementResultItemExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemExtIEsValueFieldWithoutReplay(v *WLANMeasurementResultItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureFraming(v WLANMeasurementResultItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureSemantics(v WLANMeasurementResultItemExtIEsValue, a0 q4.SemanticCapture) WLANMeasurementResultItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureSnapshot(v WLANMeasurementResultItemExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodCompareSemantics(v WLANMeasurementResultItemExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodDecode(v WLANMeasurementResultItemExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (WLANMeasurementResultItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodEncode(v WLANMeasurementResultItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodEncodeFresh(v WLANMeasurementResultItemExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(v WLANMeasurementResultItemExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodReason(v WLANMeasurementResultItemExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeWLANMeasurementResultItemExtIEsValueMethodRule(v WLANMeasurementResultItemExtIEsValue) q4.SourceRule {
	return v.rule()
}
