// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s04 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s04

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
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
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.MeasurementQuantitiesValueExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasurementQuantitiesValueExtIEsExtField) WithoutReplay() MeasurementQuantitiesValueExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *MeasurementQuantitiesValueExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *MeasurementQuantitiesValueExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *MeasurementQuantitiesValueExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesValueExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.MeasurementQuantitiesValueExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// NRCGIExtIEsExtField is the concrete ProtocolExtensionField[NRCGIExtIEsValue].
type NRCGIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.NRCGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NRCGIExtIEsExtField) WithoutReplay() NRCGIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *NRCGIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *NRCGIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeNRCGIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeNRCGIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *NRCGIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGIExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.NRCGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeNRCGIExtIEsValueMethodReason(zero, v.Id), s02.BridgeNRCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s02.BridgeNRCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PRSFrequencyHoppingConfigurationItemIEsExtField is the concrete ProtocolExtensionField[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.PRSFrequencyHoppingConfigurationItemIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSFrequencyHoppingConfigurationItemIEsExtField) WithoutReplay() PRSFrequencyHoppingConfigurationItemIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PRSFrequencyHoppingConfigurationItemIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PRSFrequencyHoppingConfigurationItemIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *PRSFrequencyHoppingConfigurationItemIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSFrequencyHoppingConfigurationItemIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.PRSFrequencyHoppingConfigurationItemIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodReason(zero, v.Id), s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultRSRPItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.ResultRSRPItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRPItemExtIEsExtField) WithoutReplay() ResultRSRPItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultRSRPItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRPItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultRSRPItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultRSRPItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultRSRPItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRPItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultRSRPItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultRSRPItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultRSRPItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeResultRSRPItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultRSRQItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.ResultRSRQItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRQItemExtIEsExtField) WithoutReplay() ResultRSRQItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultRSRQItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRQItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultRSRQItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultRSRQItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultRSRQItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRQItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultRSRQItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultRSRQItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultRSRQItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeResultRSRQItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultGERANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.ResultGERANItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultGERANItemExtIEsExtField) WithoutReplay() ResultGERANItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultGERANItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultGERANItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultGERANItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultGERANItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultGERANItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultGERANItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultGERANItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultGERANItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultGERANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeResultGERANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultUTRANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.ResultUTRANItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultUTRANItemExtIEsExtField) WithoutReplay() ResultUTRANItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultUTRANItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultUTRANItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultUTRANItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultUTRANItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultUTRANItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultUTRANItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultUTRANItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultUTRANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeResultUTRANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ResultsPerSSBIndexItemExtIEsExtField is the concrete ProtocolExtensionField[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.ResultsPerSSBIndexItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultsPerSSBIndexItemExtIEsExtField) WithoutReplay() ResultsPerSSBIndexItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultsPerSSBIndexItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultsPerSSBIndexItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultsPerSSBIndexItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultsPerSSBIndexItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultsPerSSBIndexItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// TDDConfigurationExtIEsExtField is the concrete ProtocolExtensionField[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.TDDConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TDDConfigurationExtIEsExtField) WithoutReplay() TDDConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *TDDConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *TDDConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeTDDConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeTDDConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *TDDConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TDDConfigurationExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.TDDConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeTDDConfigurationExtIEsValueMethodReason(zero, v.Id), s03.BridgeTDDConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeTDDConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.WLANMeasurementQuantitiesValueExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesValueExtIEsExtField) WithoutReplay() WLANMeasurementQuantitiesValueExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *WLANMeasurementQuantitiesValueExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementQuantitiesValueExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *WLANMeasurementQuantitiesValueExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesValueExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.WLANMeasurementQuantitiesValueExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementResultItemExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.WLANMeasurementResultItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementResultItemExtIEsExtField) WithoutReplay() WLANMeasurementResultItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *WLANMeasurementResultItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementResultItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeWLANMeasurementResultItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *WLANMeasurementResultItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementResultItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.WLANMeasurementResultItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeWLANMeasurementResultItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeWLANMeasurementResultItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeWLANMeasurementResultItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOACellsExtIEsExtField is the concrete ProtocolExtensionField[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.OTDOACellsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOACellsExtIEsExtField) WithoutReplay() OTDOACellsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOACellsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOACellsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeOTDOACellsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeOTDOACellsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *OTDOACellsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellsExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.OTDOACellsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeOTDOACellsExtIEsValueMethodReason(zero, v.Id), s02.BridgeOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s02.BridgeOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PosSIBsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBsExtIEsValue].
type PosSIBsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.PosSIBsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBsExtIEsExtField) WithoutReplay() PosSIBsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PosSIBsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgePosSIBsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgePosSIBsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *PosSIBsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBsExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.PosSIBsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgePosSIBsExtIEsValueMethodReason(zero, v.Id), s03.BridgePosSIBsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgePosSIBsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// PosSIBSegmentsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.PosSIBSegmentsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBSegmentsExtIEsExtField) WithoutReplay() PosSIBSegmentsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PosSIBSegmentsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBSegmentsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgePosSIBSegmentsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgePosSIBSegmentsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *PosSIBSegmentsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBSegmentsExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.PosSIBSegmentsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgePosSIBSegmentsExtIEsValueMethodReason(zero, v.Id), s02.BridgePosSIBSegmentsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s02.BridgePosSIBSegmentsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// SystemInformationExtIEsExtField is the concrete ProtocolExtensionField[SystemInformationExtIEsValue].
type SystemInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s03.SystemInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SystemInformationExtIEsExtField) WithoutReplay() SystemInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *SystemInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *SystemInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeSystemInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeSystemInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *SystemInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SystemInformationExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.SystemInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeSystemInformationExtIEsValueMethodReason(zero, v.Id), s03.BridgeSystemInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s03.BridgeSystemInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
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
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue s02.OTDOAInformationTypeItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationTypeItemExtIEsExtField) WithoutReplay() OTDOAInformationTypeItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOAInformationTypeItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationTypeItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *OTDOAInformationTypeItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.OTDOAInformationTypeItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodReason(zero, v.Id), s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeAddOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.AddOTDOACellsExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeAddOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.AddOTDOACellsExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeAssistanceInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.AssistanceInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeAssistanceInformationExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.AssistanceInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeAssistanceInformationFailureListExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.AssistanceInformationFailureListExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeAssistanceInformationFailureListExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.AssistanceInformationFailureListExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeAssistanceInformationMetaDataExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.AssistanceInformationMetaDataExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeAssistanceInformationMetaDataExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.AssistanceInformationMetaDataExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCriticalityDiagnosticsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.CriticalityDiagnosticsExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeCriticalityDiagnosticsExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.CriticalityDiagnosticsExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.CriticalityDiagnosticsIEListExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeCriticalityDiagnosticsIEListExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.CriticalityDiagnosticsIEListExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeECGIExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.ECGIExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeECGIExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.ECGIExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeECIDMeasurementTerminationCommandIEValueCaptureLPPaProtocolIEContainer(v *s03.ECIDMeasurementTerminationCommandIEContainer, s *aper.SemanticCapture) {
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
func BridgeECIDMeasurementTerminationCommandIEValueCompareLPPaProtocolIEContainer(v *s03.ECIDMeasurementTerminationCommandIEContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s03.InterRATMeasurementQuantitiesValueExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(v *s03.InterRATMeasurementQuantitiesValueExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(v *MeasurementQuantitiesValueExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeAddOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.AddOTDOACellsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeAddOTDOACellsExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeAddOTDOACellsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeAddOTDOACellsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeAddOTDOACellsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeAddOTDOACellsExtIEsExtFieldFieldReplay(v), *s03.BridgeAddOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAddOTDOACellsExtIEsValueCompareLPPaProtocolExtensionField(v *s03.AddOTDOACellsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeAddOTDOACellsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeAddOTDOACellsExtIEsExtFieldFieldReplay(v), *s03.BridgeAddOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.AssistanceInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeAssistanceInformationExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeAssistanceInformationExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeAssistanceInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeAssistanceInformationExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeAssistanceInformationExtIEsExtFieldFieldReplay(v), *s03.BridgeAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationExtIEsValueCompareLPPaProtocolExtensionField(v *s03.AssistanceInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeAssistanceInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeAssistanceInformationExtIEsExtFieldFieldReplay(v), *s03.BridgeAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationFailureListExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.AssistanceInformationFailureListExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReplay(v), *s03.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationFailureListExtIEsValueCompareLPPaProtocolExtensionField(v *s03.AssistanceInformationFailureListExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeAssistanceInformationFailureListExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldReplay(v), *s03.BridgeAssistanceInformationFailureListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationMetaDataExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.AssistanceInformationMetaDataExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReplay(v), *s03.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceInformationMetaDataExtIEsValueCompareLPPaProtocolExtensionField(v *s03.AssistanceInformationMetaDataExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldReplay(v), *s03.BridgeAssistanceInformationMetaDataExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.CriticalityDiagnosticsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *s03.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCompareLPPaProtocolExtensionField(v *s03.CriticalityDiagnosticsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeCriticalityDiagnosticsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *s03.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.CriticalityDiagnosticsIEListExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReplay(v), *s03.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueCompareLPPaProtocolExtensionField(v *s03.CriticalityDiagnosticsIEListExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldReplay(v), *s03.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeECGIExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.ECGIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeECGIExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeECGIExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeECGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeECGIExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeECGIExtIEsExtFieldFieldReplay(v), *s03.BridgeECGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeECGIExtIEsValueCompareLPPaProtocolExtensionField(v *s03.ECGIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeECGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeECGIExtIEsExtFieldFieldReplay(v), *s03.BridgeECGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementTerminationCommandIEValueCaptureLPPaProtocolIEField(v *s03.ECIDMeasurementTerminationCommandIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeECIDMeasurementTerminationCommandIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureFraming(v.Value))
	v.Value = s02.BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s02.BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s03.BridgeECIDMeasurementTerminationCommandIEFieldFieldReplay(v), *s03.BridgeECIDMeasurementTerminationCommandIEFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementTerminationCommandIEValueCompareLPPaProtocolIEField(v *s03.ECIDMeasurementTerminationCommandIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeECIDMeasurementTerminationCommandIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s03.BridgeECIDMeasurementTerminationCommandIEFieldFieldReplay(v), *s03.BridgeECIDMeasurementTerminationCommandIEFieldFieldWithoutReplay(v))
}

// interRATMeasurementQuantitiesValueExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.InterRATMeasurementQuantitiesValueExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.InterRATMeasurementQuantitiesValueExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(v *s03.InterRATMeasurementQuantitiesValueExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s03.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s03.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *s03.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(v *s03.InterRATMeasurementQuantitiesValueExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s03.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *s03.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(v *MeasurementQuantitiesValueExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(v *MeasurementQuantitiesValueExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, v.replay, v.withoutReplay)
}

// MeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.MeasurementQuantitiesValueExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasurementQuantitiesValueExtIEsIEField) WithoutReplay() MeasurementQuantitiesValueExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *MeasurementQuantitiesValueExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *MeasurementQuantitiesValueExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *MeasurementQuantitiesValueExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesValueExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.MeasurementQuantitiesValueExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.NRCGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NRCGIExtIEsIEField) WithoutReplay() NRCGIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *NRCGIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *NRCGIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeNRCGIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeNRCGIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *NRCGIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGIExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.NRCGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeNRCGIExtIEsValueMethodReason(zero, v.Id), s02.BridgeNRCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s02.BridgeNRCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.OTDOACellsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOACellsExtIEsIEField) WithoutReplay() OTDOACellsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOACellsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOACellsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeOTDOACellsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeOTDOACellsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOACellsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellsExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.OTDOACellsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeOTDOACellsExtIEsValueMethodReason(zero, v.Id), s02.BridgeOTDOACellsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s02.BridgeOTDOACellsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.OTDOAInformationTypeItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationTypeItemExtIEsIEField) WithoutReplay() OTDOAInformationTypeItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOAInformationTypeItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationTypeItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationTypeItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.OTDOAInformationTypeItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodReason(zero, v.Id), s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.PRSFrequencyHoppingConfigurationItemIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSFrequencyHoppingConfigurationItemIEsIEField) WithoutReplay() PRSFrequencyHoppingConfigurationItemIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PRSFrequencyHoppingConfigurationItemIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PRSFrequencyHoppingConfigurationItemIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *PRSFrequencyHoppingConfigurationItemIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSFrequencyHoppingConfigurationItemIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.PRSFrequencyHoppingConfigurationItemIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodReason(zero, v.Id), s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s02.PosSIBSegmentsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBSegmentsExtIEsIEField) WithoutReplay() PosSIBSegmentsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PosSIBSegmentsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBSegmentsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s02.BridgePosSIBSegmentsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s02.BridgePosSIBSegmentsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *PosSIBSegmentsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBSegmentsExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s02.PosSIBSegmentsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s02.BridgePosSIBSegmentsExtIEsValueMethodReason(zero, v.Id), s02.BridgePosSIBSegmentsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s02.BridgePosSIBSegmentsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.PosSIBsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBsExtIEsIEField) WithoutReplay() PosSIBsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PosSIBsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PosSIBsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgePosSIBsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgePosSIBsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *PosSIBsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBsExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.PosSIBsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgePosSIBsExtIEsValueMethodReason(zero, v.Id), s03.BridgePosSIBsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgePosSIBsExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.ResultGERANItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultGERANItemExtIEsIEField) WithoutReplay() ResultGERANItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultGERANItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultGERANItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultGERANItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultGERANItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultGERANItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultGERANItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultGERANItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultGERANItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultGERANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeResultGERANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.ResultRSRPItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRPItemExtIEsIEField) WithoutReplay() ResultRSRPItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultRSRPItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRPItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultRSRPItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultRSRPItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultRSRPItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRPItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultRSRPItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultRSRPItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultRSRPItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeResultRSRPItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.ResultRSRQItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRQItemExtIEsIEField) WithoutReplay() ResultRSRQItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultRSRQItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultRSRQItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultRSRQItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultRSRQItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultRSRQItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRQItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultRSRQItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultRSRQItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultRSRQItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeResultRSRQItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.ResultUTRANItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultUTRANItemExtIEsIEField) WithoutReplay() ResultUTRANItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultUTRANItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultUTRANItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultUTRANItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultUTRANItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultUTRANItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultUTRANItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultUTRANItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultUTRANItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeResultUTRANItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.ResultsPerSSBIndexItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultsPerSSBIndexItemExtIEsIEField) WithoutReplay() ResultsPerSSBIndexItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultsPerSSBIndexItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultsPerSSBIndexItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultsPerSSBIndexItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultsPerSSBIndexItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.ResultsPerSSBIndexItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.SystemInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SystemInformationExtIEsIEField) WithoutReplay() SystemInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *SystemInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *SystemInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeSystemInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeSystemInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *SystemInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SystemInformationExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.SystemInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeSystemInformationExtIEsValueMethodReason(zero, v.Id), s03.BridgeSystemInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeSystemInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.TDDConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TDDConfigurationExtIEsIEField) WithoutReplay() TDDConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *TDDConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *TDDConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeTDDConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeTDDConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *TDDConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TDDConfigurationExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.TDDConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeTDDConfigurationExtIEsValueMethodReason(zero, v.Id), s03.BridgeTDDConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeTDDConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.WLANMeasurementQuantitiesValueExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesValueExtIEsIEField) WithoutReplay() WLANMeasurementQuantitiesValueExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *WLANMeasurementQuantitiesValueExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementQuantitiesValueExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *WLANMeasurementQuantitiesValueExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesValueExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.WLANMeasurementQuantitiesValueExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodReason(zero, v.Id), s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
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
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.WLANMeasurementResultItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementResultItemExtIEsIEField) WithoutReplay() WLANMeasurementResultItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *WLANMeasurementResultItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementResultItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeWLANMeasurementResultItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *WLANMeasurementResultItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementResultItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero s03.WLANMeasurementResultItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeWLANMeasurementResultItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeWLANMeasurementResultItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := s03.BridgeWLANMeasurementResultItemExtIEsValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementResultItemExtIEsIEContainer is the concrete ProtocolIEContainer[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsIEContainer []WLANMeasurementResultItemExtIEsIEField

// MarshalAPERWLANChannelListTo appends a WLANChannelList list to bb.
func BridgeMarshalAPERWLANChannelListTo(list s00.WLANChannelList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERWLANChannelListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeIntegerAligned(bb, int64(elem), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo appends a PRSFrequencyHoppingConfigurationBandPositions list to bb.
func BridgeMarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(list s00.PRSFrequencyHoppingConfigurationBandPositions, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeIntegerBigBoundsAligned(bb, elem, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound7, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

type MeasurementQuantitiesValueExtIETable struct{}

func MeasurementQuantitiesValueExtIEs() MeasurementQuantitiesValueExtIETable {
	return MeasurementQuantitiesValueExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (MeasurementQuantitiesValueExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantitiesValue-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t MeasurementQuantitiesValueExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MeasurementQuantitiesValueExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return MeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return MeasurementQuantitiesValueExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.MeasurementQuantitiesValueExtIEsValue {
			sealed := s02.MeasurementQuantitiesValueExtIEsValue{}
			*s02.BridgeMeasurementQuantitiesValueExtIEsValueFieldId(&sealed) = id
			*s02.BridgeMeasurementQuantitiesValueExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NRCGIExtIETable struct{}

func NRCGIExtIEs() NRCGIExtIETable { return NRCGIExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (NRCGIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "NR-CGI-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t NRCGIExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (NRCGIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NRCGIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NRCGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NRCGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return NRCGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return NRCGIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.NRCGIExtIEsValue {
			sealed := s02.NRCGIExtIEsValue{}
			*s02.BridgeNRCGIExtIEsValueFieldId(&sealed) = id
			*s02.BridgeNRCGIExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeNRCGIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type OTDOACellsExtIETable struct{}

func OTDOACellsExtIEs() OTDOACellsExtIETable { return OTDOACellsExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (OTDOACellsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "OTDOACells-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t OTDOACellsExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OTDOACellsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOACellsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OTDOACellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOACellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOACellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return OTDOACellsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.OTDOACellsExtIEsValue {
			sealed := s02.OTDOACellsExtIEsValue{}
			*s02.BridgeOTDOACellsExtIEsValueFieldId(&sealed) = id
			*s02.BridgeOTDOACellsExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeOTDOACellsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PRSFrequencyHoppingConfigurationItemIETable struct{}

func PRSFrequencyHoppingConfigurationItemIEs() PRSFrequencyHoppingConfigurationItemIETable {
	return PRSFrequencyHoppingConfigurationItemIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (PRSFrequencyHoppingConfigurationItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "PRSFrequencyHoppingConfiguration-Item-IEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t PRSFrequencyHoppingConfigurationItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PRSFrequencyHoppingConfigurationItemIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PRSFrequencyHoppingConfigurationItemIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PRSFrequencyHoppingConfigurationItemIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PRSFrequencyHoppingConfigurationItemIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return PRSFrequencyHoppingConfigurationItemIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PRSFrequencyHoppingConfigurationItemIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.PRSFrequencyHoppingConfigurationItemIEsValue {
			sealed := s02.PRSFrequencyHoppingConfigurationItemIEsValue{}
			*s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldId(&sealed) = id
			*s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PosSIBSegmentsExtIETable struct{}

func PosSIBSegmentsExtIEs() PosSIBSegmentsExtIETable { return PosSIBSegmentsExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (PosSIBSegmentsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIB-Segments-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t PosSIBSegmentsExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PosSIBSegmentsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PosSIBSegmentsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PosSIBSegmentsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PosSIBSegmentsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return PosSIBSegmentsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PosSIBSegmentsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.PosSIBSegmentsExtIEsValue {
			sealed := s02.PosSIBSegmentsExtIEsValue{}
			*s02.BridgePosSIBSegmentsExtIEsValueFieldId(&sealed) = id
			*s02.BridgePosSIBSegmentsExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgePosSIBSegmentsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PosSIBsExtIETable struct{}

func PosSIBsExtIEs() PosSIBsExtIETable { return PosSIBsExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (PosSIBsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIBs-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t PosSIBsExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PosSIBsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PosSIBsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PosSIBsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PosSIBsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return PosSIBsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PosSIBsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.PosSIBsExtIEsValue {
			sealed := s03.PosSIBsExtIEsValue{}
			*s03.BridgePosSIBsExtIEsValueFieldId(&sealed) = id
			*s03.BridgePosSIBsExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgePosSIBsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ResultGERANItemExtIETable struct{}

func ResultGERANItemExtIEs() ResultGERANItemExtIETable { return ResultGERANItemExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ResultGERANItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultGERAN-Item-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ResultGERANItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResultGERANItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultGERANItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResultGERANItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultGERANItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultGERANItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ResultGERANItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.ResultGERANItemExtIEsValue {
			sealed := s03.ResultGERANItemExtIEsValue{}
			*s03.BridgeResultGERANItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeResultGERANItemExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeResultGERANItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ResultRSRPItemExtIETable struct{}

func ResultRSRPItemExtIEs() ResultRSRPItemExtIETable { return ResultRSRPItemExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ResultRSRPItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRP-Item-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ResultRSRPItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResultRSRPItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultRSRPItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResultRSRPItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultRSRPItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultRSRPItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ResultRSRPItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.ResultRSRPItemExtIEsValue {
			sealed := s03.ResultRSRPItemExtIEsValue{}
			*s03.BridgeResultRSRPItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeResultRSRPItemExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeResultRSRPItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ResultRSRQItemExtIETable struct{}

func ResultRSRQItemExtIEs() ResultRSRQItemExtIETable { return ResultRSRQItemExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ResultRSRQItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultRSRQ-Item-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ResultRSRQItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResultRSRQItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultRSRQItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResultRSRQItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultRSRQItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultRSRQItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ResultRSRQItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.ResultRSRQItemExtIEsValue {
			sealed := s03.ResultRSRQItemExtIEsValue{}
			*s03.BridgeResultRSRQItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeResultRSRQItemExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeResultRSRQItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ResultUTRANItemExtIETable struct{}

func ResultUTRANItemExtIEs() ResultUTRANItemExtIETable { return ResultUTRANItemExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ResultUTRANItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultUTRAN-Item-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ResultUTRANItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResultUTRANItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultUTRANItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResultUTRANItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultUTRANItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultUTRANItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ResultUTRANItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.ResultUTRANItemExtIEsValue {
			sealed := s03.ResultUTRANItemExtIEsValue{}
			*s03.BridgeResultUTRANItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeResultUTRANItemExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeResultUTRANItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ResultsPerSSBIndexItemExtIETable struct{}

func ResultsPerSSBIndexItemExtIEs() ResultsPerSSBIndexItemExtIETable {
	return ResultsPerSSBIndexItemExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (ResultsPerSSBIndexItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultsPerSSB-Index-Item-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ResultsPerSSBIndexItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResultsPerSSBIndexItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultsPerSSBIndexItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResultsPerSSBIndexItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultsPerSSBIndexItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultsPerSSBIndexItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ResultsPerSSBIndexItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.ResultsPerSSBIndexItemExtIEsValue {
			sealed := s03.ResultsPerSSBIndexItemExtIEsValue{}
			*s03.BridgeResultsPerSSBIndexItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeResultsPerSSBIndexItemExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeResultsPerSSBIndexItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SystemInformationExtIETable struct{}

func SystemInformationExtIEs() SystemInformationExtIETable { return SystemInformationExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (SystemInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "SystemInformation-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t SystemInformationExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (SystemInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SystemInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SystemInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SystemInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return SystemInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SystemInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.SystemInformationExtIEsValue {
			sealed := s03.SystemInformationExtIEsValue{}
			*s03.BridgeSystemInformationExtIEsValueFieldId(&sealed) = id
			*s03.BridgeSystemInformationExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeSystemInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type TDDConfigurationExtIETable struct{}

func TDDConfigurationExtIEs() TDDConfigurationExtIETable { return TDDConfigurationExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (TDDConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "TDDConfiguration-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t TDDConfigurationExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (TDDConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TDDConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TDDConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TDDConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return TDDConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TDDConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.TDDConfigurationExtIEsValue {
			sealed := s03.TDDConfigurationExtIEsValue{}
			*s03.BridgeTDDConfigurationExtIEsValueFieldId(&sealed) = id
			*s03.BridgeTDDConfigurationExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeTDDConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type WLANMeasurementQuantitiesValueExtIETable struct{}

func WLANMeasurementQuantitiesValueExtIEs() WLANMeasurementQuantitiesValueExtIETable {
	return WLANMeasurementQuantitiesValueExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (WLANMeasurementQuantitiesValueExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantitiesValue-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t WLANMeasurementQuantitiesValueExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (WLANMeasurementQuantitiesValueExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WLANMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return WLANMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WLANMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return WLANMeasurementQuantitiesValueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return WLANMeasurementQuantitiesValueExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.WLANMeasurementQuantitiesValueExtIEsValue {
			sealed := s03.WLANMeasurementQuantitiesValueExtIEsValue{}
			*s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldId(&sealed) = id
			*s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type WLANMeasurementResultItemExtIETable struct{}

func WLANMeasurementResultItemExtIEs() WLANMeasurementResultItemExtIETable {
	return WLANMeasurementResultItemExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (WLANMeasurementResultItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementResult-Item-ExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t WLANMeasurementResultItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (WLANMeasurementResultItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WLANMeasurementResultItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return WLANMeasurementResultItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WLANMeasurementResultItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return WLANMeasurementResultItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return WLANMeasurementResultItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.WLANMeasurementResultItemExtIEsValue {
			sealed := s03.WLANMeasurementResultItemExtIEsValue{}
			*s03.BridgeWLANMeasurementResultItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeWLANMeasurementResultItemExtIEsValueFieldOpaque(&sealed) = retained
			*s03.BridgeWLANMeasurementResultItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationTypeItemExtIETable struct{}

func OTDOAInformationTypeItemExtIEs() OTDOAInformationTypeItemExtIETable {
	return OTDOAInformationTypeItemExtIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (OTDOAInformationTypeItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-Type-ItemExtIEs"}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t OTDOAInformationTypeItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OTDOAInformationTypeItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationTypeItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OTDOAInformationTypeItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationTypeItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationTypeItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return OTDOAInformationTypeItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s02.OTDOAInformationTypeItemExtIEsValue {
			sealed := s02.OTDOAInformationTypeItemExtIEsValue{}
			*s02.BridgeOTDOAInformationTypeItemExtIEsValueFieldId(&sealed) = id
			*s02.BridgeOTDOAInformationTypeItemExtIEsValueFieldOpaque(&sealed) = retained
			*s02.BridgeOTDOAInformationTypeItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// LPPATransactionIDCodec binds the complete source value type.
func LPPATransactionIDCodec() s00.LPPATransactionIDValueCodec {
	return func() s00.LPPATransactionIDValueCodec {
		sealed := s00.LPPATransactionIDValueCodec{}
		*s00.BridgeLPPATransactionIDValueCodecFieldPath(&sealed) = "LPPATransactionID"
		*s00.BridgeLPPATransactionIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LPPATransactionID, error) {
			var zero s00.LPPATransactionID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "LPPATransactionID"); err != nil {
				return zero, err
			}
			return s00.LPPATransactionID(decoded), nil
		}
		*s00.BridgeLPPATransactionIDValueCodecFieldEncode(&sealed) = func(value s00.LPPATransactionID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeLPPATransactionIDValueCodecFieldCapture(&sealed) = func(v s00.LPPATransactionID, options aper.DecodeState) (s00.LPPATransactionID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaLPPATransactionID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*s00.BridgeLPPATransactionIDValueCodecFieldCompare(&sealed) = func(v s00.LPPATransactionID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaLPPATransactionID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeLPPATransactionIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LPPATransactionID"
			return sealed
		}()
		return sealed
	}()

}

// NRARFCNCodec binds the complete source value type.
func NRARFCNCodec() s00.NRARFCNValueCodec {
	return func() s00.NRARFCNValueCodec {
		sealed := s00.NRARFCNValueCodec{}
		*s00.BridgeNRARFCNValueCodecFieldPath(&sealed) = "NRARFCN"
		*s00.BridgeNRARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRARFCN, error) {
			var zero s00.NRARFCN
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(3279165), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NRARFCN"); err != nil {
				return zero, err
			}
			return s00.NRARFCN(decoded), nil
		}
		*s00.BridgeNRARFCNValueCodecFieldEncode(&sealed) = func(value s00.NRARFCN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(3279165), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNRARFCNValueCodecFieldCapture(&sealed) = func(v s00.NRARFCN, options aper.DecodeState) (s00.NRARFCN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureLPPaNRARFCN(&v, &s)
			var root aper.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeNRARFCNValueCodecFieldCompare(&sealed) = func(v s00.NRARFCN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(
				root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaNRARFCN(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeNRARFCNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRARFCN"
			return sealed
		}()
		return sealed
	}()

}

// NRPCICodec binds the complete source value type.
func NRPCICodec() s00.NRPCIValueCodec {
	return func() s00.NRPCIValueCodec {
		sealed := s00.NRPCIValueCodec{}
		*s00.BridgeNRPCIValueCodecFieldPath(&sealed) = "NRPCI"
		*s00.BridgeNRPCIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRPCI, error) {
			var zero s00.NRPCI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1007), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NRPCI"); err != nil {
				return zero, err
			}
			return s00.NRPCI(decoded), nil
		}
		*s00.BridgeNRPCIValueCodecFieldEncode(&sealed) = func(value s00.NRPCI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1007), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNRPCIValueCodecFieldCapture(&sealed) = func(v s00.NRPCI, options aper.DecodeState) (s00.NRPCI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNRPCI(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeNRPCIValueCodecFieldCompare(&sealed) = func(v s00.NRPCI, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s02.BridgeCompareLPPaNRPCI(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s00.BridgeNRPCIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRPCI"
			return sealed
		}()
		return sealed
	}()

}

// ProcedureCodeCodec binds the complete source value type.
func ProcedureCodeCodec() s01.ProcedureCodeValueCodec {
	return func() s01.ProcedureCodeValueCodec {
		sealed := s01.ProcedureCodeValueCodec{}
		*s01.BridgeProcedureCodeValueCodecFieldPath(&sealed) = "ProcedureCode"
		*s01.BridgeProcedureCodeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ProcedureCode, error) {
			var zero s00.ProcedureCode
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProcedureCode"); err != nil {
				return zero, err
			}
			return s00.ProcedureCode(decoded), nil
		}
		*s01.BridgeProcedureCodeValueCodecFieldEncode(&sealed) = func(value s00.ProcedureCode, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeProcedureCodeValueCodecFieldCapture(&sealed) = func(v s00.ProcedureCode, options aper.DecodeState) (s00.ProcedureCode, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaProcedureCode(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeProcedureCodeValueCodecFieldCompare(&sealed) = func(v s00.ProcedureCode, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaProcedureCode(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeProcedureCodeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProcedureCode"
			return sealed
		}()
		return sealed
	}()

}

// ProtocolIEIDCodec binds the complete source value type.
func ProtocolIEIDCodec() s01.ProtocolIEIDValueCodec {
	return func() s01.ProtocolIEIDValueCodec {
		sealed := s01.ProtocolIEIDValueCodec{}
		*s01.BridgeProtocolIEIDValueCodecFieldPath(&sealed) = "ProtocolIEID"
		*s01.BridgeProtocolIEIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ProtocolIEID, error) {
			var zero s00.ProtocolIEID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEID"); err != nil {
				return zero, err
			}
			return s00.ProtocolIEID(decoded), nil
		}
		*s01.BridgeProtocolIEIDValueCodecFieldEncode(&sealed) = func(value s00.ProtocolIEID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeProtocolIEIDValueCodecFieldCapture(&sealed) = func(v s00.ProtocolIEID, options aper.DecodeState) (s00.ProtocolIEID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaProtocolIEID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeProtocolIEIDValueCodecFieldCompare(&sealed) = func(v s00.ProtocolIEID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaProtocolIEID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeProtocolIEIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEID"
			return sealed
		}()
		return sealed
	}()

}

// SSBIndexCodec binds the complete source value type.
func SSBIndexCodec() s01.SSBIndexValueCodec {
	return func() s01.SSBIndexValueCodec {
		sealed := s01.SSBIndexValueCodec{}
		*s01.BridgeSSBIndexValueCodecFieldPath(&sealed) = "SSBIndex"
		*s01.BridgeSSBIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SSBIndex, error) {
			var zero s00.SSBIndex
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(63), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SSBIndex"); err != nil {
				return zero, err
			}
			return s00.SSBIndex(decoded), nil
		}
		*s01.BridgeSSBIndexValueCodecFieldEncode(&sealed) = func(value s00.SSBIndex, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(63), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeSSBIndexValueCodecFieldCapture(&sealed) = func(v s00.SSBIndex, options aper.DecodeState) (s00.SSBIndex, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaSSBIndex(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSSBIndexValueCodecFieldCompare(&sealed) = func(v s00.SSBIndex, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s03.BridgeCompareLPPaSSBIndex(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeSSBIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SSBIndex"
			return sealed
		}()
		return sealed
	}()

}

// SSNRRSRPCodec binds the complete source value type.
func SSNRRSRPCodec() s01.SSNRRSRPValueCodec {
	return func() s01.SSNRRSRPValueCodec {
		sealed := s01.SSNRRSRPValueCodec{}
		*s01.BridgeSSNRRSRPValueCodecFieldPath(&sealed) = "SSNRRSRP"
		*s01.BridgeSSNRRSRPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SSNRRSRP, error) {
			var zero s00.SSNRRSRP
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SSNRRSRP"); err != nil {
				return zero, err
			}
			return s00.SSNRRSRP(decoded), nil
		}
		*s01.BridgeSSNRRSRPValueCodecFieldEncode(&sealed) = func(value s00.SSNRRSRP, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeSSNRRSRPValueCodecFieldCapture(&sealed) = func(v s00.SSNRRSRP, options aper.DecodeState) (s00.SSNRRSRP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaSSNRRSRP(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSSNRRSRPValueCodecFieldCompare(&sealed) = func(v s00.SSNRRSRP, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s03.BridgeCompareLPPaSSNRRSRP(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeSSNRRSRPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SSNRRSRP"
			return sealed
		}()
		return sealed
	}()

}

// SSNRRSRQCodec binds the complete source value type.
func SSNRRSRQCodec() s01.SSNRRSRQValueCodec {
	return func() s01.SSNRRSRQValueCodec {
		sealed := s01.SSNRRSRQValueCodec{}
		*s01.BridgeSSNRRSRQValueCodecFieldPath(&sealed) = "SSNRRSRQ"
		*s01.BridgeSSNRRSRQValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SSNRRSRQ, error) {
			var zero s00.SSNRRSRQ
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SSNRRSRQ"); err != nil {
				return zero, err
			}
			return s00.SSNRRSRQ(decoded), nil
		}
		*s01.BridgeSSNRRSRQValueCodecFieldEncode(&sealed) = func(value s00.SSNRRSRQ, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeSSNRRSRQValueCodecFieldCapture(&sealed) = func(v s00.SSNRRSRQ, options aper.DecodeState) (s00.SSNRRSRQ, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaSSNRRSRQ(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSSNRRSRQValueCodecFieldCompare(&sealed) = func(v s00.SSNRRSRQ, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s03.BridgeCompareLPPaSSNRRSRQ(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeSSNRRSRQValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SSNRRSRQ"
			return sealed
		}()
		return sealed
	}()

}

// WLANChannelCodec binds the complete source value type.
func WLANChannelCodec() s01.WLANChannelValueCodec {
	return func() s01.WLANChannelValueCodec {
		sealed := s01.WLANChannelValueCodec{}
		*s01.BridgeWLANChannelValueCodecFieldPath(&sealed) = "WLANChannel"
		*s01.BridgeWLANChannelValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANChannel, error) {
			var zero s00.WLANChannel
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANChannel"); err != nil {
				return zero, err
			}
			return s00.WLANChannel(decoded), nil
		}
		*s01.BridgeWLANChannelValueCodecFieldEncode(&sealed) = func(value s00.WLANChannel, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeWLANChannelValueCodecFieldCapture(&sealed) = func(v s00.WLANChannel, options aper.DecodeState) (s00.WLANChannel, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaWLANChannel(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*s01.BridgeWLANChannelValueCodecFieldCompare(&sealed) = func(v s00.WLANChannel, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s03.BridgeCompareLPPaWLANChannel(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeWLANChannelValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANChannel"
			return sealed
		}()
		return sealed
	}()

}

// WLANOperatingClassCodec binds the complete source value type.
func WLANOperatingClassCodec() s02.WLANOperatingClassValueCodec {
	return func() s02.WLANOperatingClassValueCodec {
		sealed := s02.WLANOperatingClassValueCodec{}
		*s02.BridgeWLANOperatingClassValueCodecFieldPath(&sealed) = "WLANOperatingClass"
		*s02.BridgeWLANOperatingClassValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANOperatingClass, error) {
			var zero s00.WLANOperatingClass
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANOperatingClass"); err != nil {
				return zero, err
			}
			return s00.WLANOperatingClass(decoded), nil
		}
		*s02.BridgeWLANOperatingClassValueCodecFieldEncode(&sealed) = func(value s00.WLANOperatingClass, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerAligned(bb, int64(value), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s02.BridgeWLANOperatingClassValueCodecFieldCapture(&sealed) = func(v s00.WLANOperatingClass, options aper.DecodeState) (s00.WLANOperatingClass, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaWLANOperatingClass(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f,
				&root,
				false)
			return v, root
		}
		*s02.BridgeWLANOperatingClassValueCodecFieldCompare(&sealed) = func(v s00.WLANOperatingClass, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s03.BridgeCompareLPPaWLANOperatingClass(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s02.BridgeWLANOperatingClassValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANOperatingClass"
			return sealed
		}()
		return sealed
	}()

}
func BridgeLppaValidationRule(code s00.ValidationCode) aper.SourceRule {
	_ = code
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§10"}
}

// TS 36.413 V19.2.0 §10.3.4.2 supplies receiver handling, not the
// identifier-membership severity policy. §10.3.4.1A handles message type.
func BridgeLppaHandlingRules(code s00.ValidationCode) []aper.SourceRule {
	rules := []aper.SourceRule{BridgeLppaAdoptedRule(code)}
	clause := ""
	switch code {
	case s00.NotAllowed:
		clause = "§10.3.4.2"
	case s00.UnavailableOutcome:
		clause = "§10.3.4.1A"
	}
	if clause != "" {
		rules = append(rules, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: clause})
	}
	return rules
}
func BridgeLppaAdoptedRule(code s00.ValidationCode) aper.SourceRule {
	clause := "§10"
	switch code {
	case s00.MissingMandatory:
		clause = "§10.3.5"
	case s00.NotAllowed:
		clause = "§10.3.1"
	case s00.WrongCriticality:
		clause = "§10.3.2"
	case s00.RepeatedIE, s00.WrongOrder:
		clause = "§10.3.6"
	case s00.UnknownProcedure, s00.UnavailableOutcome:
		clause = "§10.3.4.1"
	}
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: clause}
}

var BridgeKnownLPPaIEIDs = map[s00.ProtocolIEID]struct{}{
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

func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldReceived(v *MeasurementQuantitiesValueExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v *MeasurementQuantitiesValueExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v *MeasurementQuantitiesValueExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v *MeasurementQuantitiesValueExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(v *MeasurementQuantitiesValueExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(v *MeasurementQuantitiesValueExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldReceived(v *MeasurementQuantitiesValueExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldReplay(v *MeasurementQuantitiesValueExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldStream(v *MeasurementQuantitiesValueExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldFieldWithoutReplay(v *MeasurementQuantitiesValueExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldMethodMarshalAPERTo(v *MeasurementQuantitiesValueExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesValueExtIEsIEFieldMethodUnmarshalAPERFrom(v *MeasurementQuantitiesValueExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIExtIEsExtFieldFieldReceived(v *NRCGIExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeNRCGIExtIEsExtFieldFieldReplay(v *NRCGIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeNRCGIExtIEsExtFieldFieldStream(v *NRCGIExtIEsExtField) *aper.WireSpan { return &v.stream }
func BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v *NRCGIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(v *NRCGIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(v *NRCGIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIExtIEsIEFieldFieldReceived(v *NRCGIExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeNRCGIExtIEsIEFieldFieldReplay(v *NRCGIExtIEsIEField) *aper.Snapshot { return &v.replay }
func BridgeNRCGIExtIEsIEFieldFieldStream(v *NRCGIExtIEsIEField) *aper.WireSpan { return &v.stream }
func BridgeNRCGIExtIEsIEFieldFieldWithoutReplay(v *NRCGIExtIEsIEField) *bool   { return &v.withoutReplay }
func BridgeNRCGIExtIEsIEFieldMethodMarshalAPERTo(v *NRCGIExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIExtIEsIEFieldMethodUnmarshalAPERFrom(v *NRCGIExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellsExtIEsExtFieldFieldReceived(v *OTDOACellsExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOACellsExtIEsExtFieldFieldReplay(v *OTDOACellsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellsExtIEsExtFieldFieldStream(v *OTDOACellsExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOACellsExtIEsExtFieldFieldWithoutReplay(v *OTDOACellsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(v *OTDOACellsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(v *OTDOACellsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellsExtIEsIEFieldFieldReceived(v *OTDOACellsExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOACellsExtIEsIEFieldFieldReplay(v *OTDOACellsExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellsExtIEsIEFieldFieldStream(v *OTDOACellsExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOACellsExtIEsIEFieldFieldWithoutReplay(v *OTDOACellsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsExtIEsIEFieldMethodMarshalAPERTo(v *OTDOACellsExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellsExtIEsIEFieldMethodUnmarshalAPERFrom(v *OTDOACellsExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReceived(v *OTDOAInformationTypeItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReplay(v *OTDOAInformationTypeItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldStream(v *OTDOAInformationTypeItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldWithoutReplay(v *OTDOAInformationTypeItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodMarshalAPERTo(v *OTDOAInformationTypeItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *OTDOAInformationTypeItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldReceived(v *OTDOAInformationTypeItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldReplay(v *OTDOAInformationTypeItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldStream(v *OTDOAInformationTypeItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldFieldWithoutReplay(v *OTDOAInformationTypeItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldMethodMarshalAPERTo(v *OTDOAInformationTypeItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationTypeItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReceived(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReplay(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldStream(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationItemIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodMarshalAPERTo(v *PRSFrequencyHoppingConfigurationItemIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodUnmarshalAPERFrom(v *PRSFrequencyHoppingConfigurationItemIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldReceived(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldReplay(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldStream(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationItemIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldMethodMarshalAPERTo(v *PRSFrequencyHoppingConfigurationItemIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsIEFieldMethodUnmarshalAPERFrom(v *PRSFrequencyHoppingConfigurationItemIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldReceived(v *PosSIBSegmentsExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldReplay(v *PosSIBSegmentsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldStream(v *PosSIBSegmentsExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgePosSIBSegmentsExtIEsExtFieldFieldWithoutReplay(v *PosSIBSegmentsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsExtIEsExtFieldMethodMarshalAPERTo(v *PosSIBSegmentsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBSegmentsExtIEsExtFieldMethodUnmarshalAPERFrom(v *PosSIBSegmentsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldReceived(v *PosSIBSegmentsExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldReplay(v *PosSIBSegmentsExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldStream(v *PosSIBSegmentsExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePosSIBSegmentsExtIEsIEFieldFieldWithoutReplay(v *PosSIBSegmentsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsExtIEsIEFieldMethodMarshalAPERTo(v *PosSIBSegmentsExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBSegmentsExtIEsIEFieldMethodUnmarshalAPERFrom(v *PosSIBSegmentsExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsExtIEsExtFieldFieldReceived(v *PosSIBsExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgePosSIBsExtIEsExtFieldFieldReplay(v *PosSIBsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePosSIBsExtIEsExtFieldFieldStream(v *PosSIBsExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgePosSIBsExtIEsExtFieldFieldWithoutReplay(v *PosSIBsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBsExtIEsExtFieldMethodMarshalAPERTo(v *PosSIBsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBsExtIEsExtFieldMethodUnmarshalAPERFrom(v *PosSIBsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsExtIEsIEFieldFieldReceived(v *PosSIBsExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePosSIBsExtIEsIEFieldFieldReplay(v *PosSIBsExtIEsIEField) *aper.Snapshot { return &v.replay }
func BridgePosSIBsExtIEsIEFieldFieldStream(v *PosSIBsExtIEsIEField) *aper.WireSpan { return &v.stream }
func BridgePosSIBsExtIEsIEFieldFieldWithoutReplay(v *PosSIBsExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgePosSIBsExtIEsIEFieldMethodMarshalAPERTo(v *PosSIBsExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBsExtIEsIEFieldMethodUnmarshalAPERFrom(v *PosSIBsExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultGERANItemExtIEsExtFieldFieldReceived(v *ResultGERANItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultGERANItemExtIEsExtFieldFieldReplay(v *ResultGERANItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemExtIEsExtFieldFieldStream(v *ResultGERANItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultGERANItemExtIEsExtFieldFieldWithoutReplay(v *ResultGERANItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultGERANItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultGERANItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultGERANItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultGERANItemExtIEsIEFieldFieldReceived(v *ResultGERANItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultGERANItemExtIEsIEFieldFieldReplay(v *ResultGERANItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemExtIEsIEFieldFieldStream(v *ResultGERANItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultGERANItemExtIEsIEFieldFieldWithoutReplay(v *ResultGERANItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultGERANItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultGERANItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultGERANItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRPItemExtIEsExtFieldFieldReceived(v *ResultRSRPItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultRSRPItemExtIEsExtFieldFieldReplay(v *ResultRSRPItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemExtIEsExtFieldFieldStream(v *ResultRSRPItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultRSRPItemExtIEsExtFieldFieldWithoutReplay(v *ResultRSRPItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultRSRPItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRPItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultRSRPItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRPItemExtIEsIEFieldFieldReceived(v *ResultRSRPItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultRSRPItemExtIEsIEFieldFieldReplay(v *ResultRSRPItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemExtIEsIEFieldFieldStream(v *ResultRSRPItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultRSRPItemExtIEsIEFieldFieldWithoutReplay(v *ResultRSRPItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultRSRPItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRPItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultRSRPItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRQItemExtIEsExtFieldFieldReceived(v *ResultRSRQItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultRSRQItemExtIEsExtFieldFieldReplay(v *ResultRSRQItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemExtIEsExtFieldFieldStream(v *ResultRSRQItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultRSRQItemExtIEsExtFieldFieldWithoutReplay(v *ResultRSRQItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultRSRQItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRQItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultRSRQItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRQItemExtIEsIEFieldFieldReceived(v *ResultRSRQItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultRSRQItemExtIEsIEFieldFieldReplay(v *ResultRSRQItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemExtIEsIEFieldFieldStream(v *ResultRSRQItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultRSRQItemExtIEsIEFieldFieldWithoutReplay(v *ResultRSRQItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultRSRQItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRQItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultRSRQItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemExtIEsExtFieldFieldReceived(v *ResultUTRANItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultUTRANItemExtIEsExtFieldFieldReplay(v *ResultUTRANItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemExtIEsExtFieldFieldStream(v *ResultUTRANItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultUTRANItemExtIEsExtFieldFieldWithoutReplay(v *ResultUTRANItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultUTRANItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultUTRANItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemExtIEsIEFieldFieldReceived(v *ResultUTRANItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultUTRANItemExtIEsIEFieldFieldReplay(v *ResultUTRANItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemExtIEsIEFieldFieldStream(v *ResultUTRANItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultUTRANItemExtIEsIEFieldFieldWithoutReplay(v *ResultUTRANItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultUTRANItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultUTRANItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReceived(v *ResultsPerSSBIndexItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReplay(v *ResultsPerSSBIndexItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldStream(v *ResultsPerSSBIndexItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldWithoutReplay(v *ResultsPerSSBIndexItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultsPerSSBIndexItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultsPerSSBIndexItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldReceived(v *ResultsPerSSBIndexItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldReplay(v *ResultsPerSSBIndexItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldStream(v *ResultsPerSSBIndexItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldFieldWithoutReplay(v *ResultsPerSSBIndexItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultsPerSSBIndexItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultsPerSSBIndexItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultsPerSSBIndexItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSystemInformationExtIEsExtFieldFieldReceived(v *SystemInformationExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeSystemInformationExtIEsExtFieldFieldReplay(v *SystemInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSystemInformationExtIEsExtFieldFieldStream(v *SystemInformationExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeSystemInformationExtIEsExtFieldFieldWithoutReplay(v *SystemInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationExtIEsExtFieldMethodMarshalAPERTo(v *SystemInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSystemInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *SystemInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSystemInformationExtIEsIEFieldFieldReceived(v *SystemInformationExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeSystemInformationExtIEsIEFieldFieldReplay(v *SystemInformationExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSystemInformationExtIEsIEFieldFieldStream(v *SystemInformationExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeSystemInformationExtIEsIEFieldFieldWithoutReplay(v *SystemInformationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationExtIEsIEFieldMethodMarshalAPERTo(v *SystemInformationExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSystemInformationExtIEsIEFieldMethodUnmarshalAPERFrom(v *SystemInformationExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTDDConfigurationExtIEsExtFieldFieldReceived(v *TDDConfigurationExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeTDDConfigurationExtIEsExtFieldFieldReplay(v *TDDConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationExtIEsExtFieldFieldStream(v *TDDConfigurationExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeTDDConfigurationExtIEsExtFieldFieldWithoutReplay(v *TDDConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *TDDConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTDDConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *TDDConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTDDConfigurationExtIEsIEFieldFieldReceived(v *TDDConfigurationExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeTDDConfigurationExtIEsIEFieldFieldReplay(v *TDDConfigurationExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationExtIEsIEFieldFieldStream(v *TDDConfigurationExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeTDDConfigurationExtIEsIEFieldFieldWithoutReplay(v *TDDConfigurationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationExtIEsIEFieldMethodMarshalAPERTo(v *TDDConfigurationExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTDDConfigurationExtIEsIEFieldMethodUnmarshalAPERFrom(v *TDDConfigurationExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReceived(v *WLANMeasurementQuantitiesValueExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v *WLANMeasurementQuantitiesValueExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v *WLANMeasurementQuantitiesValueExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v *WLANMeasurementQuantitiesValueExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(v *WLANMeasurementQuantitiesValueExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesValueExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldReceived(v *WLANMeasurementQuantitiesValueExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldReplay(v *WLANMeasurementQuantitiesValueExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldStream(v *WLANMeasurementQuantitiesValueExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldFieldWithoutReplay(v *WLANMeasurementQuantitiesValueExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldMethodMarshalAPERTo(v *WLANMeasurementQuantitiesValueExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsIEFieldMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesValueExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldReceived(v *WLANMeasurementResultItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldReplay(v *WLANMeasurementResultItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldStream(v *WLANMeasurementResultItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldFieldWithoutReplay(v *WLANMeasurementResultItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldMethodMarshalAPERTo(v *WLANMeasurementResultItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *WLANMeasurementResultItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldReceived(v *WLANMeasurementResultItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldReplay(v *WLANMeasurementResultItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldStream(v *WLANMeasurementResultItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldFieldWithoutReplay(v *WLANMeasurementResultItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldMethodMarshalAPERTo(v *WLANMeasurementResultItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementResultItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *WLANMeasurementResultItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
