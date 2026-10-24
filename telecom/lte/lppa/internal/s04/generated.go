// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s04 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s04

import (
	q7 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// MeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsExtContainer []MeasurementQuantitiesValueExtIEsExtField

// NRCGIExtIEsExtContainer is the concrete ProtocolExtensionContainer[NRCGIExtIEsValue].
type NRCGIExtIEsExtContainer []NRCGIExtIEsExtField

// PRSFrequencyHoppingConfigurationItemIEsExtContainer is the concrete ProtocolExtensionContainer[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsExtContainer []PRSFrequencyHoppingConfigurationItemIEsExtField

// ResultRSRPItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsExtContainer []ResultRSRPItemExtIEsExtField

// ResultRSRQItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsExtContainer []ResultRSRQItemExtIEsExtField

// ResultGERANItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsExtContainer []ResultGERANItemExtIEsExtField

// ResultUTRANItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsExtContainer []ResultUTRANItemExtIEsExtField

// ResultsPerSSBIndexItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsExtContainer []ResultsPerSSBIndexItemExtIEsExtField

// TDDConfigurationExtIEsExtContainer is the concrete ProtocolExtensionContainer[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsExtContainer []TDDConfigurationExtIEsExtField

// WLANMeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsExtContainer []WLANMeasurementQuantitiesValueExtIEsExtField

// WLANMeasurementResultItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsExtContainer []WLANMeasurementResultItemExtIEsExtField

// OTDOACellsExtIEsExtContainer is the concrete ProtocolExtensionContainer[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsExtContainer []OTDOACellsExtIEsExtField

// PosSIBsExtIEsExtContainer is the concrete ProtocolExtensionContainer[PosSIBsExtIEsValue].
type PosSIBsExtIEsExtContainer []PosSIBsExtIEsExtField

// PosSIBSegmentsExtIEsExtContainer is the concrete ProtocolExtensionContainer[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsExtContainer []PosSIBSegmentsExtIEsExtField

// SystemInformationExtIEsExtContainer is the concrete ProtocolExtensionContainer[SystemInformationExtIEsValue].
type SystemInformationExtIEsExtContainer []SystemInformationExtIEsExtField

// MeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.MeasurementQuantitiesValueExtIEsValue

	received q4.CompletePadding
}

func (v MeasurementQuantitiesValueExtIEsExtField) WithoutReplay() MeasurementQuantitiesValueExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *MeasurementQuantitiesValueExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *MeasurementQuantitiesValueExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *MeasurementQuantitiesValueExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesValueExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.MeasurementQuantitiesValueExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// NRCGIExtIEsExtField is the concrete ProtocolExtensionField[NRCGIExtIEsValue].
type NRCGIExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.NRCGIExtIEsValue

	received q4.CompletePadding
}

func (v NRCGIExtIEsExtField) WithoutReplay() NRCGIExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *NRCGIExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *NRCGIExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeNRCGIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeNRCGIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *NRCGIExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGIExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.NRCGIExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeNRCGIExtIEsValueMethodReason(zero, v.Id), q6.BridgeNRCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeNRCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PRSFrequencyHoppingConfigurationItemIEsExtField is the concrete ProtocolExtensionField[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.PRSFrequencyHoppingConfigurationItemIEsValue

	received q4.CompletePadding
}

func (v PRSFrequencyHoppingConfigurationItemIEsExtField) WithoutReplay() PRSFrequencyHoppingConfigurationItemIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *PRSFrequencyHoppingConfigurationItemIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PRSFrequencyHoppingConfigurationItemIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *PRSFrequencyHoppingConfigurationItemIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSFrequencyHoppingConfigurationItemIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.PRSFrequencyHoppingConfigurationItemIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodReason(zero, v.Id), q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultRSRPItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.ResultRSRPItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultRSRPItemExtIEsExtField) WithoutReplay() ResultRSRPItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultRSRPItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRPItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultRSRPItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultRSRPItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultRSRPItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRPItemExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultRSRPItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultRSRPItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultRSRPItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeResultRSRPItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultRSRQItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.ResultRSRQItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultRSRQItemExtIEsExtField) WithoutReplay() ResultRSRQItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultRSRQItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRQItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultRSRQItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultRSRQItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultRSRQItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRQItemExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultRSRQItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultRSRQItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultRSRQItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeResultRSRQItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultGERANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.ResultGERANItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultGERANItemExtIEsExtField) WithoutReplay() ResultGERANItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultGERANItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultGERANItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultGERANItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultGERANItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultGERANItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultGERANItemExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultGERANItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultGERANItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultGERANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeResultGERANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultUTRANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.ResultUTRANItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultUTRANItemExtIEsExtField) WithoutReplay() ResultUTRANItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultUTRANItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultUTRANItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultUTRANItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultUTRANItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultUTRANItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItemExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultUTRANItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultUTRANItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultUTRANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeResultUTRANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultsPerSSBIndexItemExtIEsExtField is the concrete ProtocolExtensionField[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.ResultsPerSSBIndexItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultsPerSSBIndexItemExtIEsExtField) WithoutReplay() ResultsPerSSBIndexItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultsPerSSBIndexItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultsPerSSBIndexItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultsPerSSBIndexItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultsPerSSBIndexItemExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultsPerSSBIndexItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// TDDConfigurationExtIEsExtField is the concrete ProtocolExtensionField[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.TDDConfigurationExtIEsValue

	received q4.CompletePadding
}

func (v TDDConfigurationExtIEsExtField) WithoutReplay() TDDConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *TDDConfigurationExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *TDDConfigurationExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeTDDConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeTDDConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *TDDConfigurationExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TDDConfigurationExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.TDDConfigurationExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeTDDConfigurationExtIEsValueMethodReason(zero, v.Id), q9.BridgeTDDConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeTDDConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.WLANMeasurementQuantitiesValueExtIEsValue

	received q4.CompletePadding
}

func (v WLANMeasurementQuantitiesValueExtIEsExtField) WithoutReplay() WLANMeasurementQuantitiesValueExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *WLANMeasurementQuantitiesValueExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementQuantitiesValueExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *WLANMeasurementQuantitiesValueExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesValueExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.WLANMeasurementQuantitiesValueExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementResultItemExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.WLANMeasurementResultItemExtIEsValue

	received q4.CompletePadding
}

func (v WLANMeasurementResultItemExtIEsExtField) WithoutReplay() WLANMeasurementResultItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *WLANMeasurementResultItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementResultItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeWLANMeasurementResultItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *WLANMeasurementResultItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementResultItemExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.WLANMeasurementResultItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeWLANMeasurementResultItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeWLANMeasurementResultItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeWLANMeasurementResultItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOACellsExtIEsExtField is the concrete ProtocolExtensionField[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.OTDOACellsExtIEsValue

	received q4.CompletePadding
}

func (v OTDOACellsExtIEsExtField) WithoutReplay() OTDOACellsExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *OTDOACellsExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOACellsExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeOTDOACellsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeOTDOACellsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *OTDOACellsExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellsExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.OTDOACellsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeOTDOACellsExtIEsValueMethodReason(zero, v.Id), q6.BridgeOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PosSIBsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBsExtIEsValue].
type PosSIBsExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.PosSIBsExtIEsValue

	received q4.CompletePadding
}

func (v PosSIBsExtIEsExtField) WithoutReplay() PosSIBsExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *PosSIBsExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBsExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgePosSIBsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgePosSIBsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *PosSIBsExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBsExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.PosSIBsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgePosSIBsExtIEsValueMethodReason(zero, v.Id), q9.BridgePosSIBsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgePosSIBsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PosSIBSegmentsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.PosSIBSegmentsExtIEsValue

	received q4.CompletePadding
}

func (v PosSIBSegmentsExtIEsExtField) WithoutReplay() PosSIBSegmentsExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *PosSIBSegmentsExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBSegmentsExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgePosSIBSegmentsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgePosSIBSegmentsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *PosSIBSegmentsExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBSegmentsExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.PosSIBSegmentsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgePosSIBSegmentsExtIEsValueMethodReason(zero, v.Id), q6.BridgePosSIBSegmentsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgePosSIBSegmentsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// SystemInformationExtIEsExtField is the concrete ProtocolExtensionField[SystemInformationExtIEsValue].
type SystemInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q9.SystemInformationExtIEsValue

	received q4.CompletePadding
}

func (v SystemInformationExtIEsExtField) WithoutReplay() SystemInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *SystemInformationExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *SystemInformationExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeSystemInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeSystemInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *SystemInformationExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SystemInformationExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.SystemInformationExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeSystemInformationExtIEsValueMethodReason(zero, v.Id), q9.BridgeSystemInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q9.BridgeSystemInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOAInformationTypeItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsExtContainer []OTDOAInformationTypeItemExtIEsExtField

// OTDOAInformationTypeItemExtIEsExtField is the concrete ProtocolExtensionField[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue q6.OTDOAInformationTypeItemExtIEsValue

	received q4.CompletePadding
}

func (v OTDOAInformationTypeItemExtIEsExtField) WithoutReplay() OTDOAInformationTypeItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *OTDOAInformationTypeItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationTypeItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *OTDOAInformationTypeItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeItemExtIEsExtField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.OTDOAInformationTypeItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodReason(zero, v.Id), q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeAddOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.AddOTDOACellsExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAddOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAddOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.AddOTDOACellsExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAddOTDOACellsExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeAssistanceInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.AssistanceInformationExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAssistanceInformationExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAssistanceInformationExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.AssistanceInformationExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAssistanceInformationExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeAssistanceInformationFailureListExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.AssistanceInformationFailureListExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAssistanceInformationFailureListExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAssistanceInformationFailureListExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.AssistanceInformationFailureListExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAssistanceInformationFailureListExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeAssistanceInformationMetaDataExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.AssistanceInformationMetaDataExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAssistanceInformationMetaDataExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAssistanceInformationMetaDataExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.AssistanceInformationMetaDataExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeAssistanceInformationMetaDataExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCriticalityDiagnosticsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.CriticalityDiagnosticsExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCriticalityDiagnosticsExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeCriticalityDiagnosticsExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.CriticalityDiagnosticsExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCriticalityDiagnosticsExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.CriticalityDiagnosticsIEListExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCriticalityDiagnosticsIEListExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.CriticalityDiagnosticsIEListExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCriticalityDiagnosticsIEListExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeECGIExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.ECGIExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeECGIExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeECGIExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.ECGIExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeECGIExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeECIDMeasurementTerminationCommandIEValueCaptureLPPaProtocolIEContainer(v *q9.ECIDMeasurementTerminationCommandIEContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeECIDMeasurementTerminationCommandIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeECIDMeasurementTerminationCommandIEValueCompareLPPaProtocolIEContainer(v *q9.ECIDMeasurementTerminationCommandIEContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeECIDMeasurementTerminationCommandIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.InterRATMeasurementQuantitiesValueExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeInterRATMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.InterRATMeasurementQuantitiesValueExtIEsExtContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeInterRATMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(v *MeasurementQuantitiesValueExtIEsExtContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAddOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.AddOTDOACellsExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeAddOTDOACellsExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeAddOTDOACellsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeAddOTDOACellsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeAddOTDOACellsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeAddOTDOACellsExtIEsExtFieldFieldReplay(v), *q9.BridgeAddOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAddOTDOACellsExtIEsValueCompareLPPaProtocolExtensionField(v *q9.AddOTDOACellsExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeAddOTDOACellsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeAddOTDOACellsExtIEsExtFieldFieldReplay(v), *q9.BridgeAddOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.AssistanceInformationExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeAssistanceInformationExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeAssistanceInformationExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeAssistanceInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeAssistanceInformationExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeAssistanceInformationExtIEsExtFieldFieldReplay(v), *q9.BridgeAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationExtIEsValueCompareLPPaProtocolExtensionField(v *q9.AssistanceInformationExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeAssistanceInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeAssistanceInformationExtIEsExtFieldFieldReplay(v), *q9.BridgeAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationFailureListExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.AssistanceInformationFailureListExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReplay(v), *q9.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationFailureListExtIEsValueCompareLPPaProtocolExtensionField(v *q9.AssistanceInformationFailureListExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeAssistanceInformationFailureListExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReplay(v), *q9.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationMetaDataExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.AssistanceInformationMetaDataExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReplay(v), *q9.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationMetaDataExtIEsValueCompareLPPaProtocolExtensionField(v *q9.AssistanceInformationMetaDataExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeAssistanceInformationMetaDataExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReplay(v), *q9.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.CriticalityDiagnosticsExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *q9.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCompareLPPaProtocolExtensionField(v *q9.CriticalityDiagnosticsExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeCriticalityDiagnosticsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *q9.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.CriticalityDiagnosticsIEListExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReplay(v), *q9.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueCompareLPPaProtocolExtensionField(v *q9.CriticalityDiagnosticsIEListExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReplay(v), *q9.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeECGIExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.ECGIExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeECGIExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeECGIExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeECGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeECGIExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeECGIExtIEsExtFieldFieldReplay(v), *q9.BridgeECGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeECGIExtIEsValueCompareLPPaProtocolExtensionField(v *q9.ECGIExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeECGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeECGIExtIEsExtFieldFieldReplay(v), *q9.BridgeECGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementTerminationCommandIEValueCaptureLPPaProtocolIEField(v *q9.ECIDMeasurementTerminationCommandIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeECIDMeasurementTerminationCommandIEFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureFraming(v.Value))
	v.Value = q6.BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q6.BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q9.BridgeECIDMeasurementTerminationCommandIEFieldFieldReplay(v), *q9.BridgeECIDMeasurementTerminationCommandIEFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementTerminationCommandIEValueCompareLPPaProtocolIEField(v *q9.ECIDMeasurementTerminationCommandIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeECIDMeasurementTerminationCommandIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q9.BridgeECIDMeasurementTerminationCommandIEFieldFieldReplay(v), *q9.BridgeECIDMeasurementTerminationCommandIEFieldFieldWithoutReplay(v))
}

// interRATMeasurementQuantitiesValueExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q6.InterRATMeasurementQuantitiesValueExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q6.InterRATMeasurementQuantitiesValueExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.InterRATMeasurementQuantitiesValueExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *q9.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(v *q9.InterRATMeasurementQuantitiesValueExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *q9.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(v *MeasurementQuantitiesValueExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(v *MeasurementQuantitiesValueExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q6.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, v.replay, v.withoutReplay)
}

// MeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.MeasurementQuantitiesValueExtIEsValue

	received q4.CompletePadding
}

func (v MeasurementQuantitiesValueExtIEsIEField) WithoutReplay() MeasurementQuantitiesValueExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *MeasurementQuantitiesValueExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *MeasurementQuantitiesValueExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *MeasurementQuantitiesValueExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesValueExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.MeasurementQuantitiesValueExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// MeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsIEContainer []MeasurementQuantitiesValueExtIEsIEField

// NRCGIExtIEsIEField is the concrete ProtocolIEField[NRCGIExtIEsValue].
type NRCGIExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.NRCGIExtIEsValue

	received q4.CompletePadding
}

func (v NRCGIExtIEsIEField) WithoutReplay() NRCGIExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *NRCGIExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *NRCGIExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeNRCGIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeNRCGIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *NRCGIExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGIExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.NRCGIExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeNRCGIExtIEsValueMethodReason(zero, v.Id), q6.BridgeNRCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeNRCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// NRCGIExtIEsIEContainer is the concrete ProtocolIEContainer[NRCGIExtIEsValue].
type NRCGIExtIEsIEContainer []NRCGIExtIEsIEField

// OTDOACellsExtIEsIEField is the concrete ProtocolIEField[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.OTDOACellsExtIEsValue

	received q4.CompletePadding
}

func (v OTDOACellsExtIEsIEField) WithoutReplay() OTDOACellsExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *OTDOACellsExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOACellsExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeOTDOACellsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeOTDOACellsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOACellsExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellsExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.OTDOACellsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeOTDOACellsExtIEsValueMethodReason(zero, v.Id), q6.BridgeOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOACellsExtIEsIEContainer is the concrete ProtocolIEContainer[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsIEContainer []OTDOACellsExtIEsIEField

// OTDOAInformationTypeItemExtIEsIEField is the concrete ProtocolIEField[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.OTDOAInformationTypeItemExtIEsValue

	received q4.CompletePadding
}

func (v OTDOAInformationTypeItemExtIEsIEField) WithoutReplay() OTDOAInformationTypeItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *OTDOAInformationTypeItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationTypeItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationTypeItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeItemExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.OTDOAInformationTypeItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodReason(zero, v.Id), q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgeOTDOAInformationTypeItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOAInformationTypeItemExtIEsIEContainer is the concrete ProtocolIEContainer[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsIEContainer []OTDOAInformationTypeItemExtIEsIEField

// PRSFrequencyHoppingConfigurationItemIEsIEField is the concrete ProtocolIEField[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.PRSFrequencyHoppingConfigurationItemIEsValue

	received q4.CompletePadding
}

func (v PRSFrequencyHoppingConfigurationItemIEsIEField) WithoutReplay() PRSFrequencyHoppingConfigurationItemIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *PRSFrequencyHoppingConfigurationItemIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PRSFrequencyHoppingConfigurationItemIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *PRSFrequencyHoppingConfigurationItemIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSFrequencyHoppingConfigurationItemIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.PRSFrequencyHoppingConfigurationItemIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodReason(zero, v.Id), q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PRSFrequencyHoppingConfigurationItemIEsIEContainer is the concrete ProtocolIEContainer[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsIEContainer []PRSFrequencyHoppingConfigurationItemIEsIEField

// PosSIBSegmentsExtIEsIEField is the concrete ProtocolIEField[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q6.PosSIBSegmentsExtIEsValue

	received q4.CompletePadding
}

func (v PosSIBSegmentsExtIEsIEField) WithoutReplay() PosSIBSegmentsExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *PosSIBSegmentsExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBSegmentsExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q6.BridgePosSIBSegmentsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q6.BridgePosSIBSegmentsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *PosSIBSegmentsExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBSegmentsExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q6.PosSIBSegmentsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q6.BridgePosSIBSegmentsExtIEsValueMethodReason(zero, v.Id), q6.BridgePosSIBSegmentsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q6.BridgePosSIBSegmentsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PosSIBSegmentsExtIEsIEContainer is the concrete ProtocolIEContainer[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsIEContainer []PosSIBSegmentsExtIEsIEField

// PosSIBsExtIEsIEField is the concrete ProtocolIEField[PosSIBsExtIEsValue].
type PosSIBsExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.PosSIBsExtIEsValue

	received q4.CompletePadding
}

func (v PosSIBsExtIEsIEField) WithoutReplay() PosSIBsExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *PosSIBsExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBsExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgePosSIBsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgePosSIBsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *PosSIBsExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBsExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.PosSIBsExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgePosSIBsExtIEsValueMethodReason(zero, v.Id), q9.BridgePosSIBsExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgePosSIBsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PosSIBsExtIEsIEContainer is the concrete ProtocolIEContainer[PosSIBsExtIEsValue].
type PosSIBsExtIEsIEContainer []PosSIBsExtIEsIEField

// ResultGERANItemExtIEsIEField is the concrete ProtocolIEField[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.ResultGERANItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultGERANItemExtIEsIEField) WithoutReplay() ResultGERANItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultGERANItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultGERANItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultGERANItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultGERANItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultGERANItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultGERANItemExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultGERANItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultGERANItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultGERANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeResultGERANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultGERANItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsIEContainer []ResultGERANItemExtIEsIEField

// ResultRSRPItemExtIEsIEField is the concrete ProtocolIEField[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.ResultRSRPItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultRSRPItemExtIEsIEField) WithoutReplay() ResultRSRPItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultRSRPItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRPItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultRSRPItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultRSRPItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultRSRPItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRPItemExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultRSRPItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultRSRPItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultRSRPItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeResultRSRPItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultRSRPItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsIEContainer []ResultRSRPItemExtIEsIEField

// ResultRSRQItemExtIEsIEField is the concrete ProtocolIEField[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.ResultRSRQItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultRSRQItemExtIEsIEField) WithoutReplay() ResultRSRQItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultRSRQItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRQItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultRSRQItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultRSRQItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultRSRQItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRQItemExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultRSRQItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultRSRQItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultRSRQItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeResultRSRQItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultRSRQItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsIEContainer []ResultRSRQItemExtIEsIEField

// ResultUTRANItemExtIEsIEField is the concrete ProtocolIEField[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.ResultUTRANItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultUTRANItemExtIEsIEField) WithoutReplay() ResultUTRANItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultUTRANItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultUTRANItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultUTRANItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultUTRANItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultUTRANItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItemExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultUTRANItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultUTRANItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultUTRANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeResultUTRANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultUTRANItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsIEContainer []ResultUTRANItemExtIEsIEField

// ResultsPerSSBIndexItemExtIEsIEField is the concrete ProtocolIEField[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.ResultsPerSSBIndexItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultsPerSSBIndexItemExtIEsIEField) WithoutReplay() ResultsPerSSBIndexItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultsPerSSBIndexItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultsPerSSBIndexItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultsPerSSBIndexItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultsPerSSBIndexItemExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.ResultsPerSSBIndexItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeResultsPerSSBIndexItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultsPerSSBIndexItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsIEContainer []ResultsPerSSBIndexItemExtIEsIEField

// SystemInformationExtIEsIEField is the concrete ProtocolIEField[SystemInformationExtIEsValue].
type SystemInformationExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.SystemInformationExtIEsValue

	received q4.CompletePadding
}

func (v SystemInformationExtIEsIEField) WithoutReplay() SystemInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *SystemInformationExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *SystemInformationExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeSystemInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeSystemInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *SystemInformationExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SystemInformationExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.SystemInformationExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeSystemInformationExtIEsValueMethodReason(zero, v.Id), q9.BridgeSystemInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeSystemInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// SystemInformationExtIEsIEContainer is the concrete ProtocolIEContainer[SystemInformationExtIEsValue].
type SystemInformationExtIEsIEContainer []SystemInformationExtIEsIEField

// TDDConfigurationExtIEsIEField is the concrete ProtocolIEField[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.TDDConfigurationExtIEsValue

	received q4.CompletePadding
}

func (v TDDConfigurationExtIEsIEField) WithoutReplay() TDDConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *TDDConfigurationExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *TDDConfigurationExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeTDDConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeTDDConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *TDDConfigurationExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TDDConfigurationExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.TDDConfigurationExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeTDDConfigurationExtIEsValueMethodReason(zero, v.Id), q9.BridgeTDDConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeTDDConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// TDDConfigurationExtIEsIEContainer is the concrete ProtocolIEContainer[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsIEContainer []TDDConfigurationExtIEsIEField

// WLANMeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.WLANMeasurementQuantitiesValueExtIEsValue

	received q4.CompletePadding
}

func (v WLANMeasurementQuantitiesValueExtIEsIEField) WithoutReplay() WLANMeasurementQuantitiesValueExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *WLANMeasurementQuantitiesValueExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementQuantitiesValueExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *WLANMeasurementQuantitiesValueExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesValueExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.WLANMeasurementQuantitiesValueExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsIEContainer []WLANMeasurementQuantitiesValueExtIEsIEField

// WLANMeasurementResultItemExtIEsIEField is the concrete ProtocolIEField[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         q9.WLANMeasurementResultItemExtIEsValue

	received q4.CompletePadding
}

func (v WLANMeasurementResultItemExtIEsIEField) WithoutReplay() WLANMeasurementResultItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *WLANMeasurementResultItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementResultItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if !q9.BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q8.WrapDecodePath(q7.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q7.Errorf("encoding criticality: %w", err)
	}
	data, err := q9.BridgeWLANMeasurementResultItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *WLANMeasurementResultItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q7.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementResultItemExtIEsIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q8.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q8.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero q9.WLANMeasurementResultItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q9.BridgeWLANMeasurementResultItemExtIEsValueMethodReason(zero, v.Id), q9.BridgeWLANMeasurementResultItemExtIEsValueMethodRule(zero))
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q9.BridgeWLANMeasurementResultItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q8.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementResultItemExtIEsIEContainer is the concrete ProtocolIEContainer[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsIEContainer []WLANMeasurementResultItemExtIEsIEField

// MarshalAPERWLANChannelListTo appends a WLANChannelList list to bb.
func BridgeMarshalAPERWLANChannelListTo(list q5.WLANChannelList, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q5.BridgeAsn1cAPERWLANChannelListListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q7.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q4.EncodeIntegerAligned(bb, int64(elem), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(255), false); err != nil {
				return q7.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo appends a PRSFrequencyHoppingConfigurationBandPositions list to bb.
func BridgeMarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(list q5.PRSFrequencyHoppingConfigurationBandPositions, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q5.BridgeAsn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q7.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q4.EncodeIntegerBigBoundsAligned(bb, elem, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound7, true); err != nil {
				return q7.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}

type MeasurementQuantitiesValueExtIETable struct{}

func MeasurementQuantitiesValueExtIEs() MeasurementQuantitiesValueExtIETable {
	return MeasurementQuantitiesValueExtIETable{}
}
func (MeasurementQuantitiesValueExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantitiesValue-ExtIEs"}
		return sealed
	}()
}
func (t MeasurementQuantitiesValueExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (MeasurementQuantitiesValueExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return MeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return MeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return MeasurementQuantitiesValueExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.MeasurementQuantitiesValueExtIEsValue {
			sealed := q6.MeasurementQuantitiesValueExtIEsValue{}
			*q6.BridgeMeasurementQuantitiesValueExtIEsValueFieldId(&sealed) = id
			*q6.BridgeMeasurementQuantitiesValueExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type NRCGIExtIETable struct{}

func NRCGIExtIEs() NRCGIExtIETable { return NRCGIExtIETable{} }
func (NRCGIExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "NR-CGI-ExtIEs"}
		return sealed
	}()
}
func (t NRCGIExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (NRCGIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NRCGIExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return NRCGIExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NRCGIExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return NRCGIExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return NRCGIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.NRCGIExtIEsValue {
			sealed := q6.NRCGIExtIEsValue{}
			*q6.BridgeNRCGIExtIEsValueFieldId(&sealed) = id
			*q6.BridgeNRCGIExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeNRCGIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type OTDOACellsExtIETable struct{}

func OTDOACellsExtIEs() OTDOACellsExtIETable { return OTDOACellsExtIETable{} }
func (OTDOACellsExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "OTDOACells-ExtIEs"}
		return sealed
	}()
}
func (t OTDOACellsExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (OTDOACellsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOACellsExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return OTDOACellsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOACellsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOACellsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return OTDOACellsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.OTDOACellsExtIEsValue {
			sealed := q6.OTDOACellsExtIEsValue{}
			*q6.BridgeOTDOACellsExtIEsValueFieldId(&sealed) = id
			*q6.BridgeOTDOACellsExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeOTDOACellsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type PRSFrequencyHoppingConfigurationItemIETable struct{}

func PRSFrequencyHoppingConfigurationItemIEs() PRSFrequencyHoppingConfigurationItemIETable {
	return PRSFrequencyHoppingConfigurationItemIETable{}
}
func (PRSFrequencyHoppingConfigurationItemIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "PRSFrequencyHoppingConfiguration-Item-IEs"}
		return sealed
	}()
}
func (t PRSFrequencyHoppingConfigurationItemIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (PRSFrequencyHoppingConfigurationItemIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PRSFrequencyHoppingConfigurationItemIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return PRSFrequencyHoppingConfigurationItemIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PRSFrequencyHoppingConfigurationItemIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return PRSFrequencyHoppingConfigurationItemIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return PRSFrequencyHoppingConfigurationItemIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.PRSFrequencyHoppingConfigurationItemIEsValue {
			sealed := q6.PRSFrequencyHoppingConfigurationItemIEsValue{}
			*q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldId(&sealed) = id
			*q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type PosSIBSegmentsExtIETable struct{}

func PosSIBSegmentsExtIEs() PosSIBSegmentsExtIETable { return PosSIBSegmentsExtIETable{} }
func (PosSIBSegmentsExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIB-Segments-ExtIEs"}
		return sealed
	}()
}
func (t PosSIBSegmentsExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (PosSIBSegmentsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PosSIBSegmentsExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return PosSIBSegmentsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PosSIBSegmentsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return PosSIBSegmentsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return PosSIBSegmentsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.PosSIBSegmentsExtIEsValue {
			sealed := q6.PosSIBSegmentsExtIEsValue{}
			*q6.BridgePosSIBSegmentsExtIEsValueFieldId(&sealed) = id
			*q6.BridgePosSIBSegmentsExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgePosSIBSegmentsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type PosSIBsExtIETable struct{}

func PosSIBsExtIEs() PosSIBsExtIETable { return PosSIBsExtIETable{} }
func (PosSIBsExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIBs-ExtIEs"}
		return sealed
	}()
}
func (t PosSIBsExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (PosSIBsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PosSIBsExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return PosSIBsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PosSIBsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return PosSIBsExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return PosSIBsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.PosSIBsExtIEsValue {
			sealed := q9.PosSIBsExtIEsValue{}
			*q9.BridgePosSIBsExtIEsValueFieldId(&sealed) = id
			*q9.BridgePosSIBsExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgePosSIBsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ResultGERANItemExtIETable struct{}

func ResultGERANItemExtIEs() ResultGERANItemExtIETable { return ResultGERANItemExtIETable{} }
func (ResultGERANItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultGERAN-Item-ExtIEs"}
		return sealed
	}()
}
func (t ResultGERANItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ResultGERANItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultGERANItemExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ResultGERANItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultGERANItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultGERANItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return ResultGERANItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.ResultGERANItemExtIEsValue {
			sealed := q9.ResultGERANItemExtIEsValue{}
			*q9.BridgeResultGERANItemExtIEsValueFieldId(&sealed) = id
			*q9.BridgeResultGERANItemExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeResultGERANItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ResultRSRPItemExtIETable struct{}

func ResultRSRPItemExtIEs() ResultRSRPItemExtIETable { return ResultRSRPItemExtIETable{} }
func (ResultRSRPItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRP-Item-ExtIEs"}
		return sealed
	}()
}
func (t ResultRSRPItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ResultRSRPItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultRSRPItemExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ResultRSRPItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultRSRPItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultRSRPItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return ResultRSRPItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.ResultRSRPItemExtIEsValue {
			sealed := q9.ResultRSRPItemExtIEsValue{}
			*q9.BridgeResultRSRPItemExtIEsValueFieldId(&sealed) = id
			*q9.BridgeResultRSRPItemExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeResultRSRPItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ResultRSRQItemExtIETable struct{}

func ResultRSRQItemExtIEs() ResultRSRQItemExtIETable { return ResultRSRQItemExtIETable{} }
func (ResultRSRQItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRQ-Item-ExtIEs"}
		return sealed
	}()
}
func (t ResultRSRQItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ResultRSRQItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultRSRQItemExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ResultRSRQItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultRSRQItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultRSRQItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return ResultRSRQItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.ResultRSRQItemExtIEsValue {
			sealed := q9.ResultRSRQItemExtIEsValue{}
			*q9.BridgeResultRSRQItemExtIEsValueFieldId(&sealed) = id
			*q9.BridgeResultRSRQItemExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeResultRSRQItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ResultUTRANItemExtIETable struct{}

func ResultUTRANItemExtIEs() ResultUTRANItemExtIETable { return ResultUTRANItemExtIETable{} }
func (ResultUTRANItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultUTRAN-Item-ExtIEs"}
		return sealed
	}()
}
func (t ResultUTRANItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ResultUTRANItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultUTRANItemExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ResultUTRANItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultUTRANItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultUTRANItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return ResultUTRANItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.ResultUTRANItemExtIEsValue {
			sealed := q9.ResultUTRANItemExtIEsValue{}
			*q9.BridgeResultUTRANItemExtIEsValueFieldId(&sealed) = id
			*q9.BridgeResultUTRANItemExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeResultUTRANItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ResultsPerSSBIndexItemExtIETable struct{}

func ResultsPerSSBIndexItemExtIEs() ResultsPerSSBIndexItemExtIETable {
	return ResultsPerSSBIndexItemExtIETable{}
}
func (ResultsPerSSBIndexItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultsPerSSB-Index-Item-ExtIEs"}
		return sealed
	}()
}
func (t ResultsPerSSBIndexItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ResultsPerSSBIndexItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultsPerSSBIndexItemExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ResultsPerSSBIndexItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultsPerSSBIndexItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultsPerSSBIndexItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return ResultsPerSSBIndexItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.ResultsPerSSBIndexItemExtIEsValue {
			sealed := q9.ResultsPerSSBIndexItemExtIEsValue{}
			*q9.BridgeResultsPerSSBIndexItemExtIEsValueFieldId(&sealed) = id
			*q9.BridgeResultsPerSSBIndexItemExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeResultsPerSSBIndexItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type SystemInformationExtIETable struct{}

func SystemInformationExtIEs() SystemInformationExtIETable { return SystemInformationExtIETable{} }
func (SystemInformationExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "SystemInformation-ExtIEs"}
		return sealed
	}()
}
func (t SystemInformationExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (SystemInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SystemInformationExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return SystemInformationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SystemInformationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return SystemInformationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return SystemInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.SystemInformationExtIEsValue {
			sealed := q9.SystemInformationExtIEsValue{}
			*q9.BridgeSystemInformationExtIEsValueFieldId(&sealed) = id
			*q9.BridgeSystemInformationExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeSystemInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type TDDConfigurationExtIETable struct{}

func TDDConfigurationExtIEs() TDDConfigurationExtIETable { return TDDConfigurationExtIETable{} }
func (TDDConfigurationExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "TDDConfiguration-ExtIEs"}
		return sealed
	}()
}
func (t TDDConfigurationExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (TDDConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TDDConfigurationExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return TDDConfigurationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TDDConfigurationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return TDDConfigurationExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return TDDConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.TDDConfigurationExtIEsValue {
			sealed := q9.TDDConfigurationExtIEsValue{}
			*q9.BridgeTDDConfigurationExtIEsValueFieldId(&sealed) = id
			*q9.BridgeTDDConfigurationExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeTDDConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type WLANMeasurementQuantitiesValueExtIETable struct{}

func WLANMeasurementQuantitiesValueExtIEs() WLANMeasurementQuantitiesValueExtIETable {
	return WLANMeasurementQuantitiesValueExtIETable{}
}
func (WLANMeasurementQuantitiesValueExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantitiesValue-ExtIEs"}
		return sealed
	}()
}
func (t WLANMeasurementQuantitiesValueExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (WLANMeasurementQuantitiesValueExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WLANMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return WLANMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WLANMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return WLANMeasurementQuantitiesValueExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return WLANMeasurementQuantitiesValueExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.WLANMeasurementQuantitiesValueExtIEsValue {
			sealed := q9.WLANMeasurementQuantitiesValueExtIEsValue{}
			*q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldId(&sealed) = id
			*q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type WLANMeasurementResultItemExtIETable struct{}

func WLANMeasurementResultItemExtIEs() WLANMeasurementResultItemExtIETable {
	return WLANMeasurementResultItemExtIETable{}
}
func (WLANMeasurementResultItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementResult-Item-ExtIEs"}
		return sealed
	}()
}
func (t WLANMeasurementResultItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (WLANMeasurementResultItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WLANMeasurementResultItemExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return WLANMeasurementResultItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WLANMeasurementResultItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return WLANMeasurementResultItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return WLANMeasurementResultItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q9.WLANMeasurementResultItemExtIEsValue {
			sealed := q9.WLANMeasurementResultItemExtIEsValue{}
			*q9.BridgeWLANMeasurementResultItemExtIEsValueFieldId(&sealed) = id
			*q9.BridgeWLANMeasurementResultItemExtIEsValueFieldOpaque(&sealed) = retained
			*q9.BridgeWLANMeasurementResultItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationTypeItemExtIETable struct{}

func OTDOAInformationTypeItemExtIEs() OTDOAInformationTypeItemExtIETable {
	return OTDOAInformationTypeItemExtIETable{}
}
func (OTDOAInformationTypeItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-Type-ItemExtIEs"}
		return sealed
	}()
}
func (t OTDOAInformationTypeItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (OTDOAInformationTypeItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationTypeItemExtIEsExtField{}, q4.OperationError(q7.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return OTDOAInformationTypeItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationTypeItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationTypeItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return OTDOAInformationTypeItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() q6.OTDOAInformationTypeItemExtIEsValue {
			sealed := q6.OTDOAInformationTypeItemExtIEsValue{}
			*q6.BridgeOTDOAInformationTypeItemExtIEsValueFieldId(&sealed) = id
			*q6.BridgeOTDOAInformationTypeItemExtIEsValueFieldOpaque(&sealed) = retained
			*q6.BridgeOTDOAInformationTypeItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

// LPPATransactionIDCodec binds the complete source value type.
func LPPATransactionIDCodec() q5.LPPATransactionIDValueCodec {
	return func() q5.LPPATransactionIDValueCodec {
		sealed := q5.LPPATransactionIDValueCodec{}
		*q5.BridgeLPPATransactionIDValueCodecFieldPath(&sealed) = "LPPATransactionID"
		*q5.BridgeLPPATransactionIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.LPPATransactionID, error) {
			var zero q5.LPPATransactionID
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(32767), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "LPPATransactionID"); err != nil {
				return zero, err
			}
			return q5.LPPATransactionID(decoded), nil
		}
		*q5.BridgeLPPATransactionIDValueCodecFieldEncode(&sealed) = func(value q5.LPPATransactionID, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(32767), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q5.BridgeLPPATransactionIDValueCodecFieldCapture(&sealed) = func(v q5.LPPATransactionID, options q4.DecodeState) (q5.LPPATransactionID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaLPPATransactionID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*q5.BridgeLPPATransactionIDValueCodecFieldCompare(&sealed) = func(v q5.LPPATransactionID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q6.BridgeCompareLPPaLPPATransactionID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeLPPATransactionIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:LPPATransactionID"
			return sealed
		}()
		return sealed
	}()

}

// NRARFCNCodec binds the complete source value type.
func NRARFCNCodec() q5.NRARFCNValueCodec {
	return func() q5.NRARFCNValueCodec {
		sealed := q5.NRARFCNValueCodec{}
		*q5.BridgeNRARFCNValueCodecFieldPath(&sealed) = "NRARFCN"
		*q5.BridgeNRARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.NRARFCN, error) {
			var zero q5.NRARFCN
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(3279165), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "NRARFCN"); err != nil {
				return zero, err
			}
			return q5.NRARFCN(decoded), nil
		}
		*q5.BridgeNRARFCNValueCodecFieldEncode(&sealed) = func(value q5.NRARFCN, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(3279165), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q5.BridgeNRARFCNValueCodecFieldCapture(&sealed) = func(v q5.NRARFCN, options q4.DecodeState) (q5.NRARFCN, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q5.BridgeCaptureLPPaNRARFCN(&v, &s)
			var root q4.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeNRARFCNValueCodecFieldCompare(&sealed) = func(v q5.NRARFCN, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(
				root, limits)
			f := s.Begin()
			q6.BridgeCompareLPPaNRARFCN(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeNRARFCNValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:NRARFCN"
			return sealed
		}()
		return sealed
	}()

}

// NRPCICodec binds the complete source value type.
func NRPCICodec() q5.NRPCIValueCodec {
	return func() q5.NRPCIValueCodec {
		sealed := q5.NRPCIValueCodec{}
		*q5.BridgeNRPCIValueCodecFieldPath(&sealed) = "NRPCI"
		*q5.BridgeNRPCIValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.NRPCI, error) {
			var zero q5.NRPCI
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(1007), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "NRPCI"); err != nil {
				return zero, err
			}
			return q5.NRPCI(decoded), nil
		}
		*q5.BridgeNRPCIValueCodecFieldEncode(&sealed) = func(value q5.NRPCI, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(1007), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q5.BridgeNRPCIValueCodecFieldCapture(&sealed) = func(v q5.NRPCI, options q4.DecodeState) (q5.NRPCI, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaNRPCI(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeNRPCIValueCodecFieldCompare(&sealed) = func(v q5.NRPCI, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			q6.BridgeCompareLPPaNRPCI(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q5.BridgeNRPCIValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:NRPCI"
			return sealed
		}()
		return sealed
	}()

}

// ProcedureCodeCodec binds the complete source value type.
func ProcedureCodeCodec() q10.ProcedureCodeValueCodec {
	return func() q10.ProcedureCodeValueCodec {
		sealed := q10.ProcedureCodeValueCodec{}
		*q10.BridgeProcedureCodeValueCodecFieldPath(&sealed) = "ProcedureCode"
		*q10.BridgeProcedureCodeValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.ProcedureCode, error) {
			var zero q5.ProcedureCode
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(255), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "ProcedureCode"); err != nil {
				return zero, err
			}
			return q5.ProcedureCode(decoded), nil
		}
		*q10.BridgeProcedureCodeValueCodecFieldEncode(&sealed) = func(value q5.ProcedureCode, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(255), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q10.BridgeProcedureCodeValueCodecFieldCapture(&sealed) = func(v q5.ProcedureCode, options q4.DecodeState) (q5.ProcedureCode, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaProcedureCode(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeProcedureCodeValueCodecFieldCompare(&sealed) = func(v q5.ProcedureCode, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q6.BridgeCompareLPPaProcedureCode(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeProcedureCodeValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ProcedureCode"
			return sealed
		}()
		return sealed
	}()

}

// ProtocolIEIDCodec binds the complete source value type.
func ProtocolIEIDCodec() q10.ProtocolIEIDValueCodec {
	return func() q10.ProtocolIEIDValueCodec {
		sealed := q10.ProtocolIEIDValueCodec{}
		*q10.BridgeProtocolIEIDValueCodecFieldPath(&sealed) = "ProtocolIEID"
		*q10.BridgeProtocolIEIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.ProtocolIEID, error) {
			var zero q5.ProtocolIEID
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "ProtocolIEID"); err != nil {
				return zero, err
			}
			return q5.ProtocolIEID(decoded), nil
		}
		*q10.BridgeProtocolIEIDValueCodecFieldEncode(&sealed) = func(value q5.ProtocolIEID, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q10.BridgeProtocolIEIDValueCodecFieldCapture(&sealed) = func(v q5.ProtocolIEID, options q4.DecodeState) (q5.ProtocolIEID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaProtocolIEID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeProtocolIEIDValueCodecFieldCompare(&sealed) = func(v q5.ProtocolIEID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q6.BridgeCompareLPPaProtocolIEID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeProtocolIEIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEID"
			return sealed
		}()
		return sealed
	}()

}

// SSBIndexCodec binds the complete source value type.
func SSBIndexCodec() q10.SSBIndexValueCodec {
	return func() q10.SSBIndexValueCodec {
		sealed := q10.SSBIndexValueCodec{}
		*q10.BridgeSSBIndexValueCodecFieldPath(&sealed) = "SSBIndex"
		*q10.BridgeSSBIndexValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.SSBIndex, error) {
			var zero q5.SSBIndex
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(63), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "SSBIndex"); err != nil {
				return zero, err
			}
			return q5.SSBIndex(decoded), nil
		}
		*q10.BridgeSSBIndexValueCodecFieldEncode(&sealed) = func(value q5.SSBIndex, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(63), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q10.BridgeSSBIndexValueCodecFieldCapture(&sealed) = func(v q5.SSBIndex, options q4.DecodeState) (q5.SSBIndex, q4.Snapshot) {
			s := q4.SemanticCaptureFor(
				options)
			f := s.Begin()
			q5.BridgeCaptureLPPaSSBIndex(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeSSBIndexValueCodecFieldCompare(&sealed) = func(v q5.SSBIndex, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaSSBIndex(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeSSBIndexValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:SSBIndex"
			return sealed
		}()
		return sealed
	}()

}

// SSNRRSRPCodec binds the complete source value type.
func SSNRRSRPCodec() q10.SSNRRSRPValueCodec {
	return func() q10.SSNRRSRPValueCodec {
		sealed := q10.SSNRRSRPValueCodec{}
		*q10.BridgeSSNRRSRPValueCodecFieldPath(&sealed) = "SSNRRSRP"
		*q10.BridgeSSNRRSRPValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.SSNRRSRP, error) {
			var zero q5.SSNRRSRP
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(127), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "SSNRRSRP"); err != nil {
				return zero, err
			}
			return q5.SSNRRSRP(decoded), nil
		}
		*q10.BridgeSSNRRSRPValueCodecFieldEncode(&sealed) = func(value q5.SSNRRSRP, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(127), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q10.BridgeSSNRRSRPValueCodecFieldCapture(&sealed) = func(v q5.SSNRRSRP, options q4.DecodeState) (q5.SSNRRSRP, q4.Snapshot) {
			s := q4.SemanticCaptureFor(
				options)
			f := s.Begin()
			q5.BridgeCaptureLPPaSSNRRSRP(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeSSNRRSRPValueCodecFieldCompare(&sealed) = func(v q5.SSNRRSRP, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaSSNRRSRP(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeSSNRRSRPValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:SSNRRSRP"
			return sealed
		}()
		return sealed
	}()

}

// SSNRRSRQCodec binds the complete source value type.
func SSNRRSRQCodec() q10.SSNRRSRQValueCodec {
	return func() q10.SSNRRSRQValueCodec {
		sealed := q10.SSNRRSRQValueCodec{}
		*q10.BridgeSSNRRSRQValueCodecFieldPath(&sealed) = "SSNRRSRQ"
		*q10.BridgeSSNRRSRQValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.SSNRRSRQ, error) {
			var zero q5.SSNRRSRQ
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(127), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "SSNRRSRQ"); err != nil {
				return zero, err
			}
			return q5.SSNRRSRQ(decoded), nil
		}
		*q10.BridgeSSNRRSRQValueCodecFieldEncode(&sealed) = func(value q5.SSNRRSRQ, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(127), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q10.BridgeSSNRRSRQValueCodecFieldCapture(&sealed) = func(v q5.SSNRRSRQ, options q4.DecodeState) (q5.SSNRRSRQ, q4.Snapshot) {
			s := q4.SemanticCaptureFor(
				options)
			f := s.Begin()
			q5.BridgeCaptureLPPaSSNRRSRQ(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeSSNRRSRQValueCodecFieldCompare(&sealed) = func(v q5.SSNRRSRQ, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaSSNRRSRQ(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeSSNRRSRQValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:SSNRRSRQ"
			return sealed
		}()
		return sealed
	}()

}

// WLANChannelCodec binds the complete source value type.
func WLANChannelCodec() q10.WLANChannelValueCodec {
	return func() q10.WLANChannelValueCodec {
		sealed := q10.WLANChannelValueCodec{}
		*q10.BridgeWLANChannelValueCodecFieldPath(&sealed) = "WLANChannel"
		*q10.BridgeWLANChannelValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.WLANChannel, error) {
			var zero q5.WLANChannel
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(255), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "WLANChannel"); err != nil {
				return zero, err
			}
			return q5.WLANChannel(decoded), nil
		}
		*q10.BridgeWLANChannelValueCodecFieldEncode(&sealed) = func(value q5.WLANChannel, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(255), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q10.BridgeWLANChannelValueCodecFieldCapture(&sealed) = func(v q5.WLANChannel, options q4.DecodeState) (q5.WLANChannel, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaWLANChannel(&v, &s)
			var root q4.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*q10.BridgeWLANChannelValueCodecFieldCompare(&sealed) = func(v q5.WLANChannel, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaWLANChannel(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeWLANChannelValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANChannel"
			return sealed
		}()
		return sealed
	}()

}

// WLANOperatingClassCodec binds the complete source value type.
func WLANOperatingClassCodec() q6.WLANOperatingClassValueCodec {
	return func() q6.WLANOperatingClassValueCodec {
		sealed := q6.WLANOperatingClassValueCodec{}
		*q6.BridgeWLANOperatingClassValueCodecFieldPath(&sealed) = "WLANOperatingClass"
		*q6.BridgeWLANOperatingClassValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.WLANOperatingClass, error) {
			var zero q5.WLANOperatingClass
			bb := q4.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q4.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(255), false)
			if err != nil {
				return zero, err
			}
			if _, err := q4.CaptureFinalBits(bb, "WLANOperatingClass"); err != nil {
				return zero, err
			}
			return q5.WLANOperatingClass(decoded), nil
		}
		*q6.BridgeWLANOperatingClassValueCodecFieldEncode(&sealed) = func(value q5.WLANOperatingClass, _ bool, budget *q4.DecodeBudget) ([]byte, error) {
			bb := q4.NewBudgetBuffer(budget)
			if err := q4.EncodeIntegerAligned(bb, int64(value), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(255), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeWLANOperatingClassValueCodecFieldCapture(&sealed) = func(v q5.WLANOperatingClass, options q4.DecodeState) (q5.WLANOperatingClass, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaWLANOperatingClass(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f,
				&root,
				false)
			return v, root
		}
		*q6.BridgeWLANOperatingClassValueCodecFieldCompare(&sealed) = func(v q5.WLANOperatingClass, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaWLANOperatingClass(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgeWLANOperatingClassValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANOperatingClass"
			return sealed
		}()
		return sealed
	}()

}
func BridgeLppaValidationRule(code q5.ValidationCode) q4.SourceRule {
	_ = code
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§10"}
}

// TS 36.413 V19.2.0 §10.3.4.2 supplies receiver handling, not the
// identifier-membership severity policy. §10.3.4.1A handles message type.
func BridgeLppaHandlingRules(code q5.ValidationCode) []q4.SourceRule {
	rules := []q4.SourceRule{BridgeLppaAdoptedRule(code)}
	clause := ""
	switch code {
	case q5.NotAllowed:
		clause = "§10.3.4.2"
	case q5.UnavailableOutcome:
		clause = "§10.3.4.1A"
	}
	if clause != "" {
		rules = append(rules, q4.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: clause})
	}
	return rules
}
func BridgeLppaAdoptedRule(code q5.ValidationCode) q4.SourceRule {
	clause := "§10"
	switch code {
	case q5.MissingMandatory:
		clause = "§10.3.5"
	case q5.NotAllowed:
		clause = "§10.3.1"
	case q5.WrongCriticality:
		clause = "§10.3.2"
	case q5.RepeatedIE, q5.WrongOrder:
		clause = "§10.3.6"
	case q5.UnknownProcedure, q5.UnavailableOutcome:
		clause = "§10.3.4.1"
	}
	return q4.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: clause}
}

var BridgeKnownLPPaIEIDs = map[q5.ProtocolIEID]struct{}{
	0:  {},
	1:  {},
	2:  {},
	3:  {},
	4:  {},
	5:  {},
	6:  {},
	7:  {},
	8:  {},
	9:  {},
	10: {},
	11: {},
	12: {},
	13: {},
	14: {},
	15: {},
	16: {},
	17: {},
	18: {},
	19: {},
	20: {},
	21: {},
	22: {},
	23: {},
	24: {},
	25: {},
	27: {},
}

func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldReceived(v *MeasurementQuantitiesValueExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v *MeasurementQuantitiesValueExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v *MeasurementQuantitiesValueExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v *MeasurementQuantitiesValueExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(v *MeasurementQuantitiesValueExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(v *MeasurementQuantitiesValueExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldReceived(v *MeasurementQuantitiesValueExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldReplay(v *MeasurementQuantitiesValueExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldStream(v *MeasurementQuantitiesValueExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldWithoutReplay(v *MeasurementQuantitiesValueExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldMethodMarshalAPERTo(v *MeasurementQuantitiesValueExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldMethodUnmarshalAPERFrom(v *MeasurementQuantitiesValueExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIExtIEsExtFieldFieldReceived(v *NRCGIExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeNRCGIExtIEsExtFieldFieldReplay(v *NRCGIExtIEsExtField) *q4.Snapshot { return &v.replay }
func BridgeNRCGIExtIEsExtFieldFieldStream(v *NRCGIExtIEsExtField) *q4.WireSpan { return &v.stream }
func BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v *NRCGIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(v *NRCGIExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(v *NRCGIExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIExtIEsIEFieldFieldReceived(v *NRCGIExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeNRCGIExtIEsIEFieldFieldReplay(v *NRCGIExtIEsIEField) *q4.Snapshot { return &v.replay }
func BridgeNRCGIExtIEsIEFieldFieldStream(v *NRCGIExtIEsIEField) *q4.WireSpan { return &v.stream }
func BridgeNRCGIExtIEsIEFieldFieldWithoutReplay(v *NRCGIExtIEsIEField) *bool { return &v.withoutReplay }
func BridgeNRCGIExtIEsIEFieldMethodMarshalAPERTo(v *NRCGIExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIExtIEsIEFieldMethodUnmarshalAPERFrom(v *NRCGIExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellsExtIEsExtFieldFieldReceived(v *OTDOACellsExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeOTDOACellsExtIEsExtFieldFieldReplay(v *OTDOACellsExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOACellsExtIEsExtFieldFieldStream(v *OTDOACellsExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOACellsExtIEsExtFieldFieldWithoutReplay(v *OTDOACellsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(v *OTDOACellsExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(v *OTDOACellsExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellsExtIEsIEFieldFieldReceived(v *OTDOACellsExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeOTDOACellsExtIEsIEFieldFieldReplay(v *OTDOACellsExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOACellsExtIEsIEFieldFieldStream(v *OTDOACellsExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOACellsExtIEsIEFieldFieldWithoutReplay(v *OTDOACellsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsExtIEsIEFieldMethodMarshalAPERTo(v *OTDOACellsExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellsExtIEsIEFieldMethodUnmarshalAPERFrom(v *OTDOACellsExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReceived(v *OTDOAInformationTypeItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReplay(v *OTDOAInformationTypeItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldStream(v *OTDOAInformationTypeItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldWithoutReplay(v *OTDOAInformationTypeItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodMarshalAPERTo(v *OTDOAInformationTypeItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *OTDOAInformationTypeItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldReceived(v *OTDOAInformationTypeItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldReplay(v *OTDOAInformationTypeItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldStream(v *OTDOAInformationTypeItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldWithoutReplay(v *OTDOAInformationTypeItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldMethodMarshalAPERTo(v *OTDOAInformationTypeItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationTypeItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReceived(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReplay(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldStream(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodMarshalAPERTo(v *PRSFrequencyHoppingConfigurationItemIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodUnmarshalAPERFrom(v *PRSFrequencyHoppingConfigurationItemIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldReceived(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldReplay(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldStream(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldMethodMarshalAPERTo(v *PRSFrequencyHoppingConfigurationItemIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldMethodUnmarshalAPERFrom(v *PRSFrequencyHoppingConfigurationItemIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldReceived(v *PosSIBSegmentsExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldReplay(v *PosSIBSegmentsExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldStream(v *PosSIBSegmentsExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldWithoutReplay(v *PosSIBSegmentsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsExtIEsExtFieldMethodMarshalAPERTo(v *PosSIBSegmentsExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBSegmentsExtIEsExtFieldMethodUnmarshalAPERFrom(v *PosSIBSegmentsExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldReceived(v *PosSIBSegmentsExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldReplay(v *PosSIBSegmentsExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldStream(v *PosSIBSegmentsExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldWithoutReplay(v *PosSIBSegmentsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsExtIEsIEFieldMethodMarshalAPERTo(v *PosSIBSegmentsExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBSegmentsExtIEsIEFieldMethodUnmarshalAPERFrom(v *PosSIBSegmentsExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsExtIEsExtFieldFieldReceived(v *PosSIBsExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgePosSIBsExtIEsExtFieldFieldReplay(v *PosSIBsExtIEsExtField) *q4.Snapshot { return &v.replay }
func BridgePosSIBsExtIEsExtFieldFieldStream(v *PosSIBsExtIEsExtField) *q4.WireSpan { return &v.stream }
func BridgePosSIBsExtIEsExtFieldFieldWithoutReplay(v *PosSIBsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBsExtIEsExtFieldMethodMarshalAPERTo(v *PosSIBsExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBsExtIEsExtFieldMethodUnmarshalAPERFrom(v *PosSIBsExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsExtIEsIEFieldFieldReceived(v *PosSIBsExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgePosSIBsExtIEsIEFieldFieldReplay(v *PosSIBsExtIEsIEField) *q4.Snapshot { return &v.replay }
func BridgePosSIBsExtIEsIEFieldFieldStream(v *PosSIBsExtIEsIEField) *q4.WireSpan { return &v.stream }
func BridgePosSIBsExtIEsIEFieldFieldWithoutReplay(v *PosSIBsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBsExtIEsIEFieldMethodMarshalAPERTo(v *PosSIBsExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBsExtIEsIEFieldMethodUnmarshalAPERFrom(v *PosSIBsExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultGERANItemExtIEsExtFieldFieldReceived(v *ResultGERANItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultGERANItemExtIEsExtFieldFieldReplay(v *ResultGERANItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemExtIEsExtFieldFieldStream(v *ResultGERANItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultGERANItemExtIEsExtFieldFieldWithoutReplay(v *ResultGERANItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultGERANItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultGERANItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultGERANItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultGERANItemExtIEsIEFieldFieldReceived(v *ResultGERANItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultGERANItemExtIEsIEFieldFieldReplay(v *ResultGERANItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemExtIEsIEFieldFieldStream(v *ResultGERANItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultGERANItemExtIEsIEFieldFieldWithoutReplay(v *ResultGERANItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultGERANItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultGERANItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultGERANItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRPItemExtIEsExtFieldFieldReceived(v *ResultRSRPItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultRSRPItemExtIEsExtFieldFieldReplay(v *ResultRSRPItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemExtIEsExtFieldFieldStream(v *ResultRSRPItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultRSRPItemExtIEsExtFieldFieldWithoutReplay(v *ResultRSRPItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultRSRPItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRPItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultRSRPItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRPItemExtIEsIEFieldFieldReceived(v *ResultRSRPItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultRSRPItemExtIEsIEFieldFieldReplay(v *ResultRSRPItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemExtIEsIEFieldFieldStream(v *ResultRSRPItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultRSRPItemExtIEsIEFieldFieldWithoutReplay(v *ResultRSRPItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultRSRPItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRPItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultRSRPItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRQItemExtIEsExtFieldFieldReceived(v *ResultRSRQItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultRSRQItemExtIEsExtFieldFieldReplay(v *ResultRSRQItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemExtIEsExtFieldFieldStream(v *ResultRSRQItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultRSRQItemExtIEsExtFieldFieldWithoutReplay(v *ResultRSRQItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultRSRQItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRQItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultRSRQItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRQItemExtIEsIEFieldFieldReceived(v *ResultRSRQItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultRSRQItemExtIEsIEFieldFieldReplay(v *ResultRSRQItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemExtIEsIEFieldFieldStream(v *ResultRSRQItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultRSRQItemExtIEsIEFieldFieldWithoutReplay(v *ResultRSRQItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultRSRQItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRQItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultRSRQItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemExtIEsExtFieldFieldReceived(v *ResultUTRANItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultUTRANItemExtIEsExtFieldFieldReplay(v *ResultUTRANItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemExtIEsExtFieldFieldStream(v *ResultUTRANItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultUTRANItemExtIEsExtFieldFieldWithoutReplay(v *ResultUTRANItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultUTRANItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultUTRANItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemExtIEsIEFieldFieldReceived(v *ResultUTRANItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultUTRANItemExtIEsIEFieldFieldReplay(v *ResultUTRANItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemExtIEsIEFieldFieldStream(v *ResultUTRANItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultUTRANItemExtIEsIEFieldFieldWithoutReplay(v *ResultUTRANItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultUTRANItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultUTRANItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReceived(v *ResultsPerSSBIndexItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReplay(v *ResultsPerSSBIndexItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldStream(v *ResultsPerSSBIndexItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldWithoutReplay(v *ResultsPerSSBIndexItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultsPerSSBIndexItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultsPerSSBIndexItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldReceived(v *ResultsPerSSBIndexItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldReplay(v *ResultsPerSSBIndexItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldStream(v *ResultsPerSSBIndexItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldWithoutReplay(v *ResultsPerSSBIndexItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultsPerSSBIndexItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultsPerSSBIndexItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSystemInformationExtIEsExtFieldFieldReceived(v *SystemInformationExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeSystemInformationExtIEsExtFieldFieldReplay(v *SystemInformationExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeSystemInformationExtIEsExtFieldFieldStream(v *SystemInformationExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeSystemInformationExtIEsExtFieldFieldWithoutReplay(v *SystemInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationExtIEsExtFieldMethodMarshalAPERTo(v *SystemInformationExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSystemInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *SystemInformationExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSystemInformationExtIEsIEFieldFieldReceived(v *SystemInformationExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeSystemInformationExtIEsIEFieldFieldReplay(v *SystemInformationExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeSystemInformationExtIEsIEFieldFieldStream(v *SystemInformationExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeSystemInformationExtIEsIEFieldFieldWithoutReplay(v *SystemInformationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationExtIEsIEFieldMethodMarshalAPERTo(v *SystemInformationExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSystemInformationExtIEsIEFieldMethodUnmarshalAPERFrom(v *SystemInformationExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTDDConfigurationExtIEsExtFieldFieldReceived(v *TDDConfigurationExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeTDDConfigurationExtIEsExtFieldFieldReplay(v *TDDConfigurationExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationExtIEsExtFieldFieldStream(v *TDDConfigurationExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeTDDConfigurationExtIEsExtFieldFieldWithoutReplay(v *TDDConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *TDDConfigurationExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTDDConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *TDDConfigurationExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTDDConfigurationExtIEsIEFieldFieldReceived(v *TDDConfigurationExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeTDDConfigurationExtIEsIEFieldFieldReplay(v *TDDConfigurationExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationExtIEsIEFieldFieldStream(v *TDDConfigurationExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeTDDConfigurationExtIEsIEFieldFieldWithoutReplay(v *TDDConfigurationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationExtIEsIEFieldMethodMarshalAPERTo(v *TDDConfigurationExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTDDConfigurationExtIEsIEFieldMethodUnmarshalAPERFrom(v *TDDConfigurationExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReceived(v *WLANMeasurementQuantitiesValueExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v *WLANMeasurementQuantitiesValueExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v *WLANMeasurementQuantitiesValueExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v *WLANMeasurementQuantitiesValueExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(v *WLANMeasurementQuantitiesValueExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesValueExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldReceived(v *WLANMeasurementQuantitiesValueExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldReplay(v *WLANMeasurementQuantitiesValueExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldStream(v *WLANMeasurementQuantitiesValueExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldWithoutReplay(v *WLANMeasurementQuantitiesValueExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldMethodMarshalAPERTo(v *WLANMeasurementQuantitiesValueExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesValueExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldReceived(v *WLANMeasurementResultItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldReplay(v *WLANMeasurementResultItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldStream(v *WLANMeasurementResultItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldWithoutReplay(v *WLANMeasurementResultItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldMethodMarshalAPERTo(v *WLANMeasurementResultItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *WLANMeasurementResultItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldReceived(v *WLANMeasurementResultItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldReplay(v *WLANMeasurementResultItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldStream(v *WLANMeasurementResultItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldWithoutReplay(v *WLANMeasurementResultItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldMethodMarshalAPERTo(v *WLANMeasurementResultItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *WLANMeasurementResultItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
