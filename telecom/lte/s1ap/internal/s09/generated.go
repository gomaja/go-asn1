// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s09 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s09

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s04 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s04"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// DeactivateTraceIEContainer is ProtocolIE-Container {{DeactivateTraceIEs}} of TS 36.413: a list of DeactivateTraceIEField values.
type DeactivateTraceIEContainer []DeactivateTraceIEField

// DeactivateTraceIEField is ProtocolIE-Field {{DeactivateTraceIEs}} of TS 36.413: an information element field.
type DeactivateTraceIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         DeactivateTraceIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DeactivateTraceIEField) WithoutReplay() DeactivateTraceIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DeactivateTraceIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DeactivateTraceIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *DeactivateTraceIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DeactivateTraceIEField{}
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
	var zero DeactivateTraceIEValue

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

// DownlinkUEAssociatedLPPaTransportIEContainer is ProtocolIE-Container {{DownlinkUEAssociatedLPPaTransport-IEs}} of TS 36.413: a list of DownlinkUEAssociatedLPPaTransportIEField values.
type DownlinkUEAssociatedLPPaTransportIEContainer []DownlinkUEAssociatedLPPaTransportIEField

// DownlinkUEAssociatedLPPaTransportIEField is ProtocolIE-Field {{DownlinkUEAssociatedLPPaTransport-IEs}} of TS 36.413: an information element field.
type DownlinkUEAssociatedLPPaTransportIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         DownlinkUEAssociatedLPPaTransportIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkUEAssociatedLPPaTransportIEField) WithoutReplay() DownlinkUEAssociatedLPPaTransportIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DownlinkUEAssociatedLPPaTransportIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DownlinkUEAssociatedLPPaTransportIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *DownlinkUEAssociatedLPPaTransportIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkUEAssociatedLPPaTransportIEField{}
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
	var zero DownlinkUEAssociatedLPPaTransportIEValue

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

// DownlinkNonUEAssociatedLPPaTransportIEContainer is ProtocolIE-Container {{DownlinkNonUEAssociatedLPPaTransport-IEs}} of TS 36.413: a list of DownlinkNonUEAssociatedLPPaTransportIEField values.
type DownlinkNonUEAssociatedLPPaTransportIEContainer []DownlinkNonUEAssociatedLPPaTransportIEField

// DownlinkNonUEAssociatedLPPaTransportIEField is ProtocolIE-Field {{DownlinkNonUEAssociatedLPPaTransport-IEs}} of TS 36.413: an information element field.
type DownlinkNonUEAssociatedLPPaTransportIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         DownlinkNonUEAssociatedLPPaTransportIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNonUEAssociatedLPPaTransportIEField) WithoutReplay() DownlinkNonUEAssociatedLPPaTransportIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DownlinkNonUEAssociatedLPPaTransportIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DownlinkNonUEAssociatedLPPaTransportIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *DownlinkNonUEAssociatedLPPaTransportIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkNonUEAssociatedLPPaTransportIEField{}
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
	var zero DownlinkNonUEAssociatedLPPaTransportIEValue

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

// CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer is ProtocolExtensionContainer {{CellIdentifierAndCELevelForCECapableUEs-ExtIEs}} of TS 36.413: a list of CellIdentifierAndCELevelForCECapableUEsExtIEsExtField values.
type CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer []CellIdentifierAndCELevelForCECapableUEsExtIEsExtField

// CellIDBroadcastItemExtIEsExtContainer is ProtocolExtensionContainer {{CellID-Broadcast-Item-ExtIEs}} of TS 36.413: a list of CellIDBroadcastItemExtIEsExtField values.
type CellIDBroadcastItemExtIEsExtContainer []CellIDBroadcastItemExtIEsExtField

// CellIDCancelledItemExtIEsExtContainer is ProtocolExtensionContainer {{CellID-Cancelled-Item-ExtIEs}} of TS 36.413: a list of CellIDCancelledItemExtIEsExtField values.
type CellIDCancelledItemExtIEsExtContainer []CellIDCancelledItemExtIEsExtField

// CellTypeExtIEsExtContainer is ProtocolExtensionContainer {{CellType-ExtIEs}} of TS 36.413: a list of CellTypeExtIEsExtField values.
type CellTypeExtIEsExtContainer []CellTypeExtIEsExtField

// ConnectedengNBItemExtIEsExtContainer is ProtocolExtensionContainer {{ConnectedengNBItem-ExtIEs}} of TS 36.413: a list of ConnectedengNBItemExtIEsExtField values.
type ConnectedengNBItemExtIEsExtContainer []ConnectedengNBItemExtIEsExtField

// ContextatSourceExtIEsExtContainer is ProtocolExtensionContainer {{ContextatSource-ExtIEs}} of TS 36.413: a list of ContextatSourceExtIEsExtField values.
type ContextatSourceExtIEsExtContainer []ContextatSourceExtIEsExtField

// CriticalityDiagnosticsExtIEsExtContainer is ProtocolExtensionContainer {{CriticalityDiagnostics-ExtIEs}} of TS 36.413: a list of CriticalityDiagnosticsExtIEsExtField values.
type CriticalityDiagnosticsExtIEsExtContainer []CriticalityDiagnosticsExtIEsExtField

// CriticalityDiagnosticsIEItemExtIEsExtContainer is ProtocolExtensionContainer {{CriticalityDiagnostics-IE-Item-ExtIEs}} of TS 36.413: a list of CriticalityDiagnosticsIEItemExtIEsExtField values.
type CriticalityDiagnosticsIEItemExtIEsExtContainer []CriticalityDiagnosticsIEItemExtIEsExtField

// DAPSRequestInfoExtIEsExtContainer is ProtocolExtensionContainer {{DAPSRequestInfo-ExtIEs}} of TS 36.413: a list of DAPSRequestInfoExtIEsExtField values.
type DAPSRequestInfoExtIEsExtContainer []DAPSRequestInfoExtIEsExtField

// DAPSResponseInfoItemExtIEsExtContainer is ProtocolExtensionContainer {{DAPSResponseInfoItem-ExtIEs}} of TS 36.413: a list of DAPSResponseInfoItemExtIEsExtField values.
type DAPSResponseInfoItemExtIEsExtContainer []DAPSResponseInfoItemExtIEsExtField

// DAPSResponseInfoExtIEsExtContainer is ProtocolExtensionContainer {{DAPSResponseInfo-ExtIEs}} of TS 36.413: a list of DAPSResponseInfoExtIEsExtField values.
type DAPSResponseInfoExtIEsExtContainer []DAPSResponseInfoExtIEsExtField

// DLCPSecurityInformationExtIEsExtContainer is ProtocolExtensionContainer {{DL-CP-SecurityInformation-ExtIEs}} of TS 36.413: a list of DLCPSecurityInformationExtIEsExtField values.
type DLCPSecurityInformationExtIEsExtContainer []DLCPSecurityInformationExtIEsExtField

// CompletedCellinEAIItemExtIEsExtContainer is ProtocolExtensionContainer {{CompletedCellinEAI-Item-ExtIEs}} of TS 36.413: a list of CompletedCellinEAIItemExtIEsExtField values.
type CompletedCellinEAIItemExtIEsExtContainer []CompletedCellinEAIItemExtIEsExtField

// ENBStatusTransferTransparentContainerExtIEsExtContainer is ProtocolExtensionContainer {{ENB-StatusTransfer-TransparentContainer-ExtIEs}} of TS 36.413: a list of ENBStatusTransferTransparentContainerExtIEsExtField values.
type ENBStatusTransferTransparentContainerExtIEsExtContainer []ENBStatusTransferTransparentContainerExtIEsExtField

// ENDCSONConfigurationTransferExtIEsExtContainer is ProtocolExtensionContainer {{EN-DCSONConfigurationTransfer-ExtIEs}} of TS 36.413: a list of ENDCSONConfigurationTransferExtIEsExtField values.
type ENDCSONConfigurationTransferExtIEsExtContainer []ENDCSONConfigurationTransferExtIEsExtField

// ENDCTransferTypeReplyExtIEsExtContainer is ProtocolExtensionContainer {{EN-DCTransferTypeReply-ExtIEs}} of TS 36.413: a list of ENDCTransferTypeReplyExtIEsExtField values.
type ENDCTransferTypeReplyExtIEsExtContainer []ENDCTransferTypeReplyExtIEsExtField

// ENDCSONeNBIdentificationExtIEsExtContainer is ProtocolExtensionContainer {{EN-DCSONeNBIdentification-ExtIEs}} of TS 36.413: a list of ENDCSONeNBIdentificationExtIEsExtField values.
type ENDCSONeNBIdentificationExtIEsExtContainer []ENDCSONeNBIdentificationExtIEsExtField

// ENDCSONengNBIdentificationExtIEsExtContainer is ProtocolExtensionContainer {{EN-DCSONengNBIdentification-ExtIEs}} of TS 36.413: a list of ENDCSONengNBIdentificationExtIEsExtField values.
type ENDCSONengNBIdentificationExtIEsExtContainer []ENDCSONengNBIdentificationExtIEsExtField

// CompletedCellinTAIItemExtIEsExtContainer is ProtocolExtensionContainer {{CompletedCellinTAI-Item-ExtIEs}} of TS 36.413: a list of CompletedCellinTAIItemExtIEsExtField values.
type CompletedCellinTAIItemExtIEsExtContainer []CompletedCellinTAIItemExtIEsExtField

// ENBX2ExtTLAExtIEsExtContainer is ProtocolExtensionContainer {{ENBX2ExtTLA-ExtIEs}} of TS 36.413: a list of ENBX2ExtTLAExtIEsExtField values.
type ENBX2ExtTLAExtIEsExtContainer []ENBX2ExtTLAExtIEsExtField

// CellIdentifierAndCELevelForCECapableUEsExtIEsExtField is ProtocolExtensionField {{CellIdentifierAndCELevelForCECapableUEs-ExtIEs}} of TS 36.413: an extension field.
type CellIdentifierAndCELevelForCECapableUEsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIdentifierAndCELevelForCECapableUEsExtIEsExtField) WithoutReplay() CellIdentifierAndCELevelForCECapableUEsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIdentifierAndCELevelForCECapableUEsExtIEsExtField{}
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
	var zero s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellIDBroadcastItemExtIEsExtField is ProtocolExtensionField {{CellID-Broadcast-Item-ExtIEs}} of TS 36.413: an extension field.
type CellIDBroadcastItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CellIDBroadcastItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDBroadcastItemExtIEsExtField) WithoutReplay() CellIDBroadcastItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellIDBroadcastItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellIDBroadcastItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellIDBroadcastItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellIDBroadcastItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellIDBroadcastItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIDBroadcastItemExtIEsExtField{}
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
	var zero s03.CellIDBroadcastItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellIDBroadcastItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellIDBroadcastItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCellIDBroadcastItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellIDCancelledItemExtIEsExtField is ProtocolExtensionField {{CellID-Cancelled-Item-ExtIEs}} of TS 36.413: an extension field.
type CellIDCancelledItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CellIDCancelledItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDCancelledItemExtIEsExtField) WithoutReplay() CellIDCancelledItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellIDCancelledItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellIDCancelledItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellIDCancelledItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellIDCancelledItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellIDCancelledItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIDCancelledItemExtIEsExtField{}
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
	var zero s03.CellIDCancelledItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellIDCancelledItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellIDCancelledItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCellIDCancelledItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellTypeExtIEsExtField is ProtocolExtensionField {{CellType-ExtIEs}} of TS 36.413: an extension field.
type CellTypeExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CellTypeExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTypeExtIEsExtField) WithoutReplay() CellTypeExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellTypeExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellTypeExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellTypeExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellTypeExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellTypeExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellTypeExtIEsExtField{}
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
	var zero s03.CellTypeExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellTypeExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellTypeExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCellTypeExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ConnectedengNBItemExtIEsExtField is ProtocolExtensionField {{ConnectedengNBItem-ExtIEs}} of TS 36.413: an extension field.
type ConnectedengNBItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.ConnectedengNBItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBItemExtIEsExtField) WithoutReplay() ConnectedengNBItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ConnectedengNBItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ConnectedengNBItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeConnectedengNBItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeConnectedengNBItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ConnectedengNBItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ConnectedengNBItemExtIEsExtField{}
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
	var zero s03.ConnectedengNBItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeConnectedengNBItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeConnectedengNBItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeConnectedengNBItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ContextatSourceExtIEsExtField is ProtocolExtensionField {{ContextatSource-ExtIEs}} of TS 36.413: an extension field.
type ContextatSourceExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.ContextatSourceExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ContextatSourceExtIEsExtField) WithoutReplay() ContextatSourceExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ContextatSourceExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ContextatSourceExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeContextatSourceExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeContextatSourceExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ContextatSourceExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ContextatSourceExtIEsExtField{}
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
	var zero s03.ContextatSourceExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeContextatSourceExtIEsValueMethodReason(zero, v.Id), s03.BridgeContextatSourceExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeContextatSourceExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CriticalityDiagnosticsExtIEsExtField is ProtocolExtensionField {{CriticalityDiagnostics-ExtIEs}} of TS 36.413: an extension field.
type CriticalityDiagnosticsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CriticalityDiagnosticsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsExtIEsExtField) WithoutReplay() CriticalityDiagnosticsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CriticalityDiagnosticsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
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
	if !s03.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CriticalityDiagnosticsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsExtIEsExtField{}
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
	var zero s03.CriticalityDiagnosticsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCriticalityDiagnosticsExtIEsValueMethodReason(zero, v.Id), s03.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CriticalityDiagnosticsIEItemExtIEsExtField is ProtocolExtensionField {{CriticalityDiagnostics-IE-Item-ExtIEs}} of TS 36.413: an extension field.
type CriticalityDiagnosticsIEItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CriticalityDiagnosticsIEItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEItemExtIEsExtField) WithoutReplay() CriticalityDiagnosticsIEItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CriticalityDiagnosticsIEItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CriticalityDiagnosticsIEItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CriticalityDiagnosticsIEItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEItemExtIEsExtField{}
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
	var zero s03.CriticalityDiagnosticsIEItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DAPSRequestInfoExtIEsExtField is ProtocolExtensionField {{DAPSRequestInfo-ExtIEs}} of TS 36.413: an extension field.
type DAPSRequestInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.DAPSRequestInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSRequestInfoExtIEsExtField) WithoutReplay() DAPSRequestInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSRequestInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSRequestInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeDAPSRequestInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeDAPSRequestInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DAPSRequestInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSRequestInfoExtIEsExtField{}
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
	var zero s03.DAPSRequestInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeDAPSRequestInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeDAPSRequestInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeDAPSRequestInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DAPSResponseInfoItemExtIEsExtField is ProtocolExtensionField {{DAPSResponseInfoItem-ExtIEs}} of TS 36.413: an extension field.
type DAPSResponseInfoItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.DAPSResponseInfoItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoItemExtIEsExtField) WithoutReplay() DAPSResponseInfoItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSResponseInfoItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSResponseInfoItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeDAPSResponseInfoItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeDAPSResponseInfoItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DAPSResponseInfoItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoItemExtIEsExtField{}
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
	var zero s04.DAPSResponseInfoItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeDAPSResponseInfoItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeDAPSResponseInfoItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeDAPSResponseInfoItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DAPSResponseInfoExtIEsExtField is ProtocolExtensionField {{DAPSResponseInfo-ExtIEs}} of TS 36.413: an extension field.
type DAPSResponseInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.DAPSResponseInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoExtIEsExtField) WithoutReplay() DAPSResponseInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSResponseInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSResponseInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeDAPSResponseInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeDAPSResponseInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DAPSResponseInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoExtIEsExtField{}
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
	var zero s03.DAPSResponseInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeDAPSResponseInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeDAPSResponseInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeDAPSResponseInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DLCPSecurityInformationExtIEsExtField is ProtocolExtensionField {{DL-CP-SecurityInformation-ExtIEs}} of TS 36.413: an extension field.
type DLCPSecurityInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.DLCPSecurityInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DLCPSecurityInformationExtIEsExtField) WithoutReplay() DLCPSecurityInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DLCPSecurityInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DLCPSecurityInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeDLCPSecurityInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeDLCPSecurityInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DLCPSecurityInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DLCPSecurityInformationExtIEsExtField{}
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
	var zero s04.DLCPSecurityInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeDLCPSecurityInformationExtIEsValueMethodReason(zero, v.Id), s04.BridgeDLCPSecurityInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeDLCPSecurityInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CompletedCellinEAIItemExtIEsExtField is ProtocolExtensionField {{CompletedCellinEAI-Item-ExtIEs}} of TS 36.413: an extension field.
type CompletedCellinEAIItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CompletedCellinEAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinEAIItemExtIEsExtField) WithoutReplay() CompletedCellinEAIItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CompletedCellinEAIItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CompletedCellinEAIItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCompletedCellinEAIItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCompletedCellinEAIItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CompletedCellinEAIItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CompletedCellinEAIItemExtIEsExtField{}
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
	var zero s03.CompletedCellinEAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCompletedCellinEAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCompletedCellinEAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCompletedCellinEAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENBStatusTransferTransparentContainerExtIEsExtField is ProtocolExtensionField {{ENB-StatusTransfer-TransparentContainer-ExtIEs}} of TS 36.413: an extension field.
type ENBStatusTransferTransparentContainerExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ENBStatusTransferTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferTransparentContainerExtIEsExtField) WithoutReplay() ENBStatusTransferTransparentContainerExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBStatusTransferTransparentContainerExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBStatusTransferTransparentContainerExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENBStatusTransferTransparentContainerExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransferTransparentContainerExtIEsExtField{}
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
	var zero s04.ENBStatusTransferTransparentContainerExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodReason(zero, v.Id), s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCSONConfigurationTransferExtIEsExtField is ProtocolExtensionField {{EN-DCSONConfigurationTransfer-ExtIEs}} of TS 36.413: an extension field.
type ENDCSONConfigurationTransferExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ENDCSONConfigurationTransferExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONConfigurationTransferExtIEsExtField) WithoutReplay() ENDCSONConfigurationTransferExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCSONConfigurationTransferExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCSONConfigurationTransferExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCSONConfigurationTransferExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONConfigurationTransferExtIEsExtField{}
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
	var zero s04.ENDCSONConfigurationTransferExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCTransferTypeReplyExtIEsExtField is ProtocolExtensionField {{EN-DCTransferTypeReply-ExtIEs}} of TS 36.413: an extension field.
type ENDCTransferTypeReplyExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ENDCTransferTypeReplyExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeReplyExtIEsExtField) WithoutReplay() ENDCTransferTypeReplyExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCTransferTypeReplyExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCTransferTypeReplyExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENDCTransferTypeReplyExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCTransferTypeReplyExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCTransferTypeReplyExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCTransferTypeReplyExtIEsExtField{}
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
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeENDCTransferTypeReplyExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCSONeNBIdentificationExtIEsExtField is ProtocolExtensionField {{EN-DCSONeNBIdentification-ExtIEs}} of TS 36.413: an extension field.
type ENDCSONeNBIdentificationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ENDCSONeNBIdentificationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONeNBIdentificationExtIEsExtField) WithoutReplay() ENDCSONeNBIdentificationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCSONeNBIdentificationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCSONeNBIdentificationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCSONeNBIdentificationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONeNBIdentificationExtIEsExtField{}
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
	var zero s04.ENDCSONeNBIdentificationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCSONengNBIdentificationExtIEsExtField is ProtocolExtensionField {{EN-DCSONengNBIdentification-ExtIEs}} of TS 36.413: an extension field.
type ENDCSONengNBIdentificationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ENDCSONengNBIdentificationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONengNBIdentificationExtIEsExtField) WithoutReplay() ENDCSONengNBIdentificationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCSONengNBIdentificationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCSONengNBIdentificationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCSONengNBIdentificationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONengNBIdentificationExtIEsExtField{}
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
	var zero s04.ENDCSONengNBIdentificationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CompletedCellinTAIItemExtIEsExtField is ProtocolExtensionField {{CompletedCellinTAI-Item-ExtIEs}} of TS 36.413: an extension field.
type CompletedCellinTAIItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CompletedCellinTAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinTAIItemExtIEsExtField) WithoutReplay() CompletedCellinTAIItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CompletedCellinTAIItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CompletedCellinTAIItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCompletedCellinTAIItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCompletedCellinTAIItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CompletedCellinTAIItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CompletedCellinTAIItemExtIEsExtField{}
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
	var zero s03.CompletedCellinTAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCompletedCellinTAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCompletedCellinTAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCompletedCellinTAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENBX2ExtTLAExtIEsExtField is ProtocolExtensionField {{ENBX2ExtTLA-ExtIEs}} of TS 36.413: an extension field.
type ENBX2ExtTLAExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s04.ENBX2ExtTLAExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBX2ExtTLAExtIEsExtField) WithoutReplay() ENBX2ExtTLAExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBX2ExtTLAExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBX2ExtTLAExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENBX2ExtTLAExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENBX2ExtTLAExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENBX2ExtTLAExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBX2ExtTLAExtIEsExtField{}
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
	var zero s04.ENBX2ExtTLAExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENBX2ExtTLAExtIEsValueMethodReason(zero, v.Id), s04.BridgeENBX2ExtTLAExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s04.BridgeENBX2ExtTLAExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DeactivateTraceMMEUES1APIDIEBinding binds MMEUES1APID to the DeactivateTraceIEs object set of TS 36.413.
type DeactivateTraceMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) DeactivateTraceIEValue

	get func(*DeactivateTraceIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DeactivateTraceMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DeactivateTraceMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b DeactivateTraceMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (DeactivateTraceIEField, error) {
	if b.inject == nil {
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return DeactivateTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DeactivateTraceMMEUES1APIDIEBinding) Get(field *DeactivateTraceIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DeactivateTraceENBUES1APIDIEBinding binds ENBUES1APID to the DeactivateTraceIEs object set of TS 36.413.
type DeactivateTraceENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) DeactivateTraceIEValue

	get func(*DeactivateTraceIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DeactivateTraceENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DeactivateTraceENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b DeactivateTraceENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (DeactivateTraceIEField, error) {
	if b.inject == nil {
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return DeactivateTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DeactivateTraceENBUES1APIDIEBinding) Get(field *DeactivateTraceIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DeactivateTraceEUTRANTraceIDIEBinding binds EUTRANTraceID to the DeactivateTraceIEs object set of TS 36.413.
type DeactivateTraceEUTRANTraceIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EUTRANTraceIDValueCodec
	inject func(s00.EUTRANTraceID,

	) DeactivateTraceIEValue

	get func(*DeactivateTraceIEValue,

	) (*s00.EUTRANTraceID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DeactivateTraceEUTRANTraceIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DeactivateTraceEUTRANTraceIDIEBinding) Codec() s00.EUTRANTraceIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b DeactivateTraceEUTRANTraceIDIEBinding) New(value s00.EUTRANTraceID,

) (DeactivateTraceIEField, error) {
	if b.inject == nil {
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEUTRANTraceIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DeactivateTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return DeactivateTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DeactivateTraceEUTRANTraceIDIEBinding) Get(field *DeactivateTraceIEField) (*s00.EUTRANTraceID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding binds RoutingID to the DownlinkNonUEAssociatedLPPaTransport-IEs object set of TS 36.413.
type DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.RoutingIDValueCodec
	inject func(s00.RoutingID,

	) DownlinkNonUEAssociatedLPPaTransportIEValue

	get func(*DownlinkNonUEAssociatedLPPaTransportIEValue,

	) (*s00.RoutingID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding) Codec() s02.RoutingIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding) New(value s00.RoutingID,

) (DownlinkNonUEAssociatedLPPaTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeRoutingIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding) Get(field *DownlinkNonUEAssociatedLPPaTransportIEField) (*s00.RoutingID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding binds LPPaPDU to the DownlinkNonUEAssociatedLPPaTransport-IEs object set of TS 36.413.
type DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding struct {
	info   s00.FieldInfo
	codec  s01.LPPaPDUValueCodec
	inject func(s00.LPPaPDU,

	) DownlinkNonUEAssociatedLPPaTransportIEValue

	get func(*DownlinkNonUEAssociatedLPPaTransportIEValue,

	) (*s00.LPPaPDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding) Codec() s01.LPPaPDUValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding) New(value s00.LPPaPDU,

) (DownlinkNonUEAssociatedLPPaTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeLPPaPDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding) Get(field *DownlinkNonUEAssociatedLPPaTransportIEField) (*s00.LPPaPDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding binds MMEUES1APID to the DownlinkUEAssociatedLPPaTransport-IEs object set of TS 36.413.
type DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) DownlinkUEAssociatedLPPaTransportIEValue

	get func(*DownlinkUEAssociatedLPPaTransportIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (DownlinkUEAssociatedLPPaTransportIEField, error) {
	if b.inject == nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding) Get(field *DownlinkUEAssociatedLPPaTransportIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding binds ENBUES1APID to the DownlinkUEAssociatedLPPaTransport-IEs object set of TS 36.413.
type DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) DownlinkUEAssociatedLPPaTransportIEValue

	get func(*DownlinkUEAssociatedLPPaTransportIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (DownlinkUEAssociatedLPPaTransportIEField, error) {
	if b.inject == nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding) Get(field *DownlinkUEAssociatedLPPaTransportIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding binds RoutingID to the DownlinkUEAssociatedLPPaTransport-IEs object set of TS 36.413.
type DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.RoutingIDValueCodec
	inject func(s00.RoutingID,

	) DownlinkUEAssociatedLPPaTransportIEValue

	get func(*DownlinkUEAssociatedLPPaTransportIEValue,

	) (*s00.RoutingID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding) Codec() s02.RoutingIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding) New(value s00.RoutingID,

) (DownlinkUEAssociatedLPPaTransportIEField, error) {
	if b.inject == nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeRoutingIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding) Get(field *DownlinkUEAssociatedLPPaTransportIEField) (*s00.RoutingID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding binds LPPaPDU to the DownlinkUEAssociatedLPPaTransport-IEs object set of TS 36.413.
type DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding struct {
	info   s00.FieldInfo
	codec  s01.LPPaPDUValueCodec
	inject func(s00.LPPaPDU,

	) DownlinkUEAssociatedLPPaTransportIEValue

	get func(*DownlinkUEAssociatedLPPaTransportIEValue,

	) (*s00.LPPaPDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding) Codec() s01.LPPaPDUValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding) New(value s00.LPPaPDU,

) (DownlinkUEAssociatedLPPaTransportIEField, error) {
	if b.inject == nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeLPPaPDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding) Get(field *DownlinkUEAssociatedLPPaTransportIEField) (*s00.LPPaPDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellBasedQMCExtIEsIEField uses the ProtocolIE-Field shape for object set CellBasedQMC-ExtIEs of TS 36.413.
type CellBasedQMCExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CellBasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedQMCExtIEsIEField) WithoutReplay() CellBasedQMCExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellBasedQMCExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellBasedQMCExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellBasedQMCExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellBasedQMCExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellBasedQMCExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedQMCExtIEsIEField{}
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
	var zero s03.CellBasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellBasedQMCExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellBasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCellBasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellBasedQMCExtIEsIEContainer uses the ProtocolIE-Container shape for object set CellBasedQMC-ExtIEs of TS 36.413: a list of CellBasedQMCExtIEsIEField values.
type CellBasedQMCExtIEsIEContainer []CellBasedQMCExtIEsIEField

// CellIDBroadcastItemExtIEsIEField uses the ProtocolIE-Field shape for object set CellID-Broadcast-Item-ExtIEs of TS 36.413.
type CellIDBroadcastItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CellIDBroadcastItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDBroadcastItemExtIEsIEField) WithoutReplay() CellIDBroadcastItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellIDBroadcastItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellIDBroadcastItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellIDBroadcastItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellIDBroadcastItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellIDBroadcastItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIDBroadcastItemExtIEsIEField{}
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
	var zero s03.CellIDBroadcastItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellIDBroadcastItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellIDBroadcastItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCellIDBroadcastItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellIDBroadcastItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CellID-Broadcast-Item-ExtIEs of TS 36.413: a list of CellIDBroadcastItemExtIEsIEField values.
type CellIDBroadcastItemExtIEsIEContainer []CellIDBroadcastItemExtIEsIEField

// CellIDCancelledItemExtIEsIEField uses the ProtocolIE-Field shape for object set CellID-Cancelled-Item-ExtIEs of TS 36.413.
type CellIDCancelledItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CellIDCancelledItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDCancelledItemExtIEsIEField) WithoutReplay() CellIDCancelledItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellIDCancelledItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellIDCancelledItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellIDCancelledItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellIDCancelledItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellIDCancelledItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIDCancelledItemExtIEsIEField{}
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
	var zero s03.CellIDCancelledItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellIDCancelledItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellIDCancelledItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCellIDCancelledItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellIDCancelledItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CellID-Cancelled-Item-ExtIEs of TS 36.413: a list of CellIDCancelledItemExtIEsIEField values.
type CellIDCancelledItemExtIEsIEContainer []CellIDCancelledItemExtIEsIEField

// CellIdentifierAndCELevelForCECapableUEsExtIEsIEField uses the ProtocolIE-Field shape for object set CellIdentifierAndCELevelForCECapableUEs-ExtIEs of TS 36.413.
type CellIdentifierAndCELevelForCECapableUEsExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIdentifierAndCELevelForCECapableUEsExtIEsIEField) WithoutReplay() CellIdentifierAndCELevelForCECapableUEsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellIdentifierAndCELevelForCECapableUEsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellIdentifierAndCELevelForCECapableUEsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellIdentifierAndCELevelForCECapableUEsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIdentifierAndCELevelForCECapableUEsExtIEsIEField{}
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
	var zero s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellIdentifierAndCELevelForCECapableUEsExtIEsIEContainer uses the ProtocolIE-Container shape for object set CellIdentifierAndCELevelForCECapableUEs-ExtIEs of TS 36.413: a list of CellIdentifierAndCELevelForCECapableUEsExtIEsIEField values.
type CellIdentifierAndCELevelForCECapableUEsExtIEsIEContainer []CellIdentifierAndCELevelForCECapableUEsExtIEsIEField

// CellTypeExtIEsIEField uses the ProtocolIE-Field shape for object set CellType-ExtIEs of TS 36.413.
type CellTypeExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CellTypeExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTypeExtIEsIEField) WithoutReplay() CellTypeExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellTypeExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellTypeExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellTypeExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellTypeExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellTypeExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellTypeExtIEsIEField{}
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
	var zero s03.CellTypeExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellTypeExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellTypeExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCellTypeExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellTypeExtIEsIEContainer uses the ProtocolIE-Container shape for object set CellType-ExtIEs of TS 36.413: a list of CellTypeExtIEsIEField values.
type CellTypeExtIEsIEContainer []CellTypeExtIEsIEField

// CompletedCellinEAIItemExtIEsIEField uses the ProtocolIE-Field shape for object set CompletedCellinEAI-Item-ExtIEs of TS 36.413.
type CompletedCellinEAIItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CompletedCellinEAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinEAIItemExtIEsIEField) WithoutReplay() CompletedCellinEAIItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CompletedCellinEAIItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CompletedCellinEAIItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCompletedCellinEAIItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCompletedCellinEAIItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CompletedCellinEAIItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CompletedCellinEAIItemExtIEsIEField{}
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
	var zero s03.CompletedCellinEAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCompletedCellinEAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCompletedCellinEAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCompletedCellinEAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CompletedCellinEAIItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CompletedCellinEAI-Item-ExtIEs of TS 36.413: a list of CompletedCellinEAIItemExtIEsIEField values.
type CompletedCellinEAIItemExtIEsIEContainer []CompletedCellinEAIItemExtIEsIEField

// CompletedCellinTAIItemExtIEsIEField uses the ProtocolIE-Field shape for object set CompletedCellinTAI-Item-ExtIEs of TS 36.413.
type CompletedCellinTAIItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CompletedCellinTAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinTAIItemExtIEsIEField) WithoutReplay() CompletedCellinTAIItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CompletedCellinTAIItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CompletedCellinTAIItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCompletedCellinTAIItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCompletedCellinTAIItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CompletedCellinTAIItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CompletedCellinTAIItemExtIEsIEField{}
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
	var zero s03.CompletedCellinTAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCompletedCellinTAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCompletedCellinTAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCompletedCellinTAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CompletedCellinTAIItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CompletedCellinTAI-Item-ExtIEs of TS 36.413: a list of CompletedCellinTAIItemExtIEsIEField values.
type CompletedCellinTAIItemExtIEsIEContainer []CompletedCellinTAIItemExtIEsIEField

// ConnectedengNBItemExtIEsIEField uses the ProtocolIE-Field shape for object set ConnectedengNBItem-ExtIEs of TS 36.413.
type ConnectedengNBItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.ConnectedengNBItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBItemExtIEsIEField) WithoutReplay() ConnectedengNBItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ConnectedengNBItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ConnectedengNBItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeConnectedengNBItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeConnectedengNBItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ConnectedengNBItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ConnectedengNBItemExtIEsIEField{}
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
	var zero s03.ConnectedengNBItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeConnectedengNBItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeConnectedengNBItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeConnectedengNBItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ConnectedengNBItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set ConnectedengNBItem-ExtIEs of TS 36.413: a list of ConnectedengNBItemExtIEsIEField values.
type ConnectedengNBItemExtIEsIEContainer []ConnectedengNBItemExtIEsIEField

// ContextatSourceExtIEsIEField uses the ProtocolIE-Field shape for object set ContextatSource-ExtIEs of TS 36.413.
type ContextatSourceExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.ContextatSourceExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ContextatSourceExtIEsIEField) WithoutReplay() ContextatSourceExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ContextatSourceExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ContextatSourceExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeContextatSourceExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeContextatSourceExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ContextatSourceExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ContextatSourceExtIEsIEField{}
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
	var zero s03.ContextatSourceExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeContextatSourceExtIEsValueMethodReason(zero, v.Id), s03.BridgeContextatSourceExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeContextatSourceExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ContextatSourceExtIEsIEContainer uses the ProtocolIE-Container shape for object set ContextatSource-ExtIEs of TS 36.413: a list of ContextatSourceExtIEsIEField values.
type ContextatSourceExtIEsIEContainer []ContextatSourceExtIEsIEField

// CriticalityDiagnosticsExtIEsIEField uses the ProtocolIE-Field shape for object set CriticalityDiagnostics-ExtIEs of TS 36.413.
type CriticalityDiagnosticsExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CriticalityDiagnosticsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsExtIEsIEField) WithoutReplay() CriticalityDiagnosticsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CriticalityDiagnosticsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
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
	if !s03.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CriticalityDiagnosticsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsExtIEsIEField{}
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
	var zero s03.CriticalityDiagnosticsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCriticalityDiagnosticsExtIEsValueMethodReason(zero, v.Id), s03.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CriticalityDiagnosticsExtIEsIEContainer uses the ProtocolIE-Container shape for object set CriticalityDiagnostics-ExtIEs of TS 36.413: a list of CriticalityDiagnosticsExtIEsIEField values.
type CriticalityDiagnosticsExtIEsIEContainer []CriticalityDiagnosticsExtIEsIEField

// CriticalityDiagnosticsIEItemExtIEsIEField uses the ProtocolIE-Field shape for object set CriticalityDiagnostics-IE-Item-ExtIEs of TS 36.413.
type CriticalityDiagnosticsIEItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CriticalityDiagnosticsIEItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEItemExtIEsIEField) WithoutReplay() CriticalityDiagnosticsIEItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CriticalityDiagnosticsIEItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CriticalityDiagnosticsIEItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CriticalityDiagnosticsIEItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEItemExtIEsIEField{}
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
	var zero s03.CriticalityDiagnosticsIEItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CriticalityDiagnosticsIEItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CriticalityDiagnostics-IE-Item-ExtIEs of TS 36.413: a list of CriticalityDiagnosticsIEItemExtIEsIEField values.
type CriticalityDiagnosticsIEItemExtIEsIEContainer []CriticalityDiagnosticsIEItemExtIEsIEField

// DAPSRequestInfoExtIEsIEField uses the ProtocolIE-Field shape for object set DAPSRequestInfo-ExtIEs of TS 36.413.
type DAPSRequestInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.DAPSRequestInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSRequestInfoExtIEsIEField) WithoutReplay() DAPSRequestInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSRequestInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSRequestInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeDAPSRequestInfoExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeDAPSRequestInfoExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DAPSRequestInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSRequestInfoExtIEsIEField{}
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
	var zero s03.DAPSRequestInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeDAPSRequestInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeDAPSRequestInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeDAPSRequestInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DAPSRequestInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set DAPSRequestInfo-ExtIEs of TS 36.413: a list of DAPSRequestInfoExtIEsIEField values.
type DAPSRequestInfoExtIEsIEContainer []DAPSRequestInfoExtIEsIEField

// DAPSResponseInfoExtIEsIEField uses the ProtocolIE-Field shape for object set DAPSResponseInfo-ExtIEs of TS 36.413.
type DAPSResponseInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.DAPSResponseInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoExtIEsIEField) WithoutReplay() DAPSResponseInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSResponseInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSResponseInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeDAPSResponseInfoExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeDAPSResponseInfoExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DAPSResponseInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoExtIEsIEField{}
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
	var zero s03.DAPSResponseInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeDAPSResponseInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeDAPSResponseInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeDAPSResponseInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DAPSResponseInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set DAPSResponseInfo-ExtIEs of TS 36.413: a list of DAPSResponseInfoExtIEsIEField values.
type DAPSResponseInfoExtIEsIEContainer []DAPSResponseInfoExtIEsIEField

// DAPSResponseInfoItemExtIEsIEField uses the ProtocolIE-Field shape for object set DAPSResponseInfoItem-ExtIEs of TS 36.413.
type DAPSResponseInfoItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.DAPSResponseInfoItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoItemExtIEsIEField) WithoutReplay() DAPSResponseInfoItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSResponseInfoItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSResponseInfoItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeDAPSResponseInfoItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeDAPSResponseInfoItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DAPSResponseInfoItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoItemExtIEsIEField{}
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
	var zero s04.DAPSResponseInfoItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeDAPSResponseInfoItemExtIEsValueMethodReason(zero, v.Id), s04.BridgeDAPSResponseInfoItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeDAPSResponseInfoItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DAPSResponseInfoItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set DAPSResponseInfoItem-ExtIEs of TS 36.413: a list of DAPSResponseInfoItemExtIEsIEField values.
type DAPSResponseInfoItemExtIEsIEContainer []DAPSResponseInfoItemExtIEsIEField

// DLCPSecurityInformationExtIEsIEField uses the ProtocolIE-Field shape for object set DL-CP-SecurityInformation-ExtIEs of TS 36.413.
type DLCPSecurityInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.DLCPSecurityInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DLCPSecurityInformationExtIEsIEField) WithoutReplay() DLCPSecurityInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DLCPSecurityInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DLCPSecurityInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeDLCPSecurityInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeDLCPSecurityInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *DLCPSecurityInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DLCPSecurityInformationExtIEsIEField{}
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
	var zero s04.DLCPSecurityInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeDLCPSecurityInformationExtIEsValueMethodReason(zero, v.Id), s04.BridgeDLCPSecurityInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeDLCPSecurityInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// DLCPSecurityInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set DL-CP-SecurityInformation-ExtIEs of TS 36.413: a list of DLCPSecurityInformationExtIEsIEField values.
type DLCPSecurityInformationExtIEsIEContainer []DLCPSecurityInformationExtIEsIEField

// ENBStatusTransferTransparentContainerExtIEsIEField uses the ProtocolIE-Field shape for object set ENB-StatusTransfer-TransparentContainer-ExtIEs of TS 36.413.
type ENBStatusTransferTransparentContainerExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ENBStatusTransferTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferTransparentContainerExtIEsIEField) WithoutReplay() ENBStatusTransferTransparentContainerExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBStatusTransferTransparentContainerExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBStatusTransferTransparentContainerExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENBStatusTransferTransparentContainerExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransferTransparentContainerExtIEsIEField{}
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
	var zero s04.ENBStatusTransferTransparentContainerExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodReason(zero, v.Id), s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENBStatusTransferTransparentContainerExtIEsIEContainer uses the ProtocolIE-Container shape for object set ENB-StatusTransfer-TransparentContainer-ExtIEs of TS 36.413: a list of ENBStatusTransferTransparentContainerExtIEsIEField values.
type ENBStatusTransferTransparentContainerExtIEsIEContainer []ENBStatusTransferTransparentContainerExtIEsIEField

// ENBX2ExtTLAExtIEsIEField uses the ProtocolIE-Field shape for object set ENBX2ExtTLA-ExtIEs of TS 36.413.
type ENBX2ExtTLAExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ENBX2ExtTLAExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBX2ExtTLAExtIEsIEField) WithoutReplay() ENBX2ExtTLAExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBX2ExtTLAExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBX2ExtTLAExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENBX2ExtTLAExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENBX2ExtTLAExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENBX2ExtTLAExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBX2ExtTLAExtIEsIEField{}
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
	var zero s04.ENBX2ExtTLAExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENBX2ExtTLAExtIEsValueMethodReason(zero, v.Id), s04.BridgeENBX2ExtTLAExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeENBX2ExtTLAExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENBX2ExtTLAExtIEsIEContainer uses the ProtocolIE-Container shape for object set ENBX2ExtTLA-ExtIEs of TS 36.413: a list of ENBX2ExtTLAExtIEsIEField values.
type ENBX2ExtTLAExtIEsIEContainer []ENBX2ExtTLAExtIEsIEField

// ENDCSONConfigurationTransferExtIEsIEField uses the ProtocolIE-Field shape for object set EN-DCSONConfigurationTransfer-ExtIEs of TS 36.413.
type ENDCSONConfigurationTransferExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ENDCSONConfigurationTransferExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONConfigurationTransferExtIEsIEField) WithoutReplay() ENDCSONConfigurationTransferExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCSONConfigurationTransferExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCSONConfigurationTransferExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCSONConfigurationTransferExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONConfigurationTransferExtIEsIEField{}
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
	var zero s04.ENDCSONConfigurationTransferExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCSONConfigurationTransferExtIEsIEContainer uses the ProtocolIE-Container shape for object set EN-DCSONConfigurationTransfer-ExtIEs of TS 36.413: a list of ENDCSONConfigurationTransferExtIEsIEField values.
type ENDCSONConfigurationTransferExtIEsIEContainer []ENDCSONConfigurationTransferExtIEsIEField

// ENDCSONeNBIdentificationExtIEsIEField uses the ProtocolIE-Field shape for object set EN-DCSONeNBIdentification-ExtIEs of TS 36.413.
type ENDCSONeNBIdentificationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ENDCSONeNBIdentificationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONeNBIdentificationExtIEsIEField) WithoutReplay() ENDCSONeNBIdentificationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCSONeNBIdentificationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCSONeNBIdentificationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCSONeNBIdentificationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONeNBIdentificationExtIEsIEField{}
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
	var zero s04.ENDCSONeNBIdentificationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCSONeNBIdentificationExtIEsIEContainer uses the ProtocolIE-Container shape for object set EN-DCSONeNBIdentification-ExtIEs of TS 36.413: a list of ENDCSONeNBIdentificationExtIEsIEField values.
type ENDCSONeNBIdentificationExtIEsIEContainer []ENDCSONeNBIdentificationExtIEsIEField

// ENDCSONengNBIdentificationExtIEsIEField uses the ProtocolIE-Field shape for object set EN-DCSONengNBIdentification-ExtIEs of TS 36.413.
type ENDCSONengNBIdentificationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s04.ENDCSONengNBIdentificationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONengNBIdentificationExtIEsIEField) WithoutReplay() ENDCSONengNBIdentificationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENDCSONengNBIdentificationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENDCSONengNBIdentificationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ENDCSONengNBIdentificationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONengNBIdentificationExtIEsIEField{}
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
	var zero s04.ENDCSONengNBIdentificationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodReason(zero, v.Id), s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ENDCSONengNBIdentificationExtIEsIEContainer uses the ProtocolIE-Container shape for object set EN-DCSONengNBIdentification-ExtIEs of TS 36.413: a list of ENDCSONengNBIdentificationExtIEsIEField values.
type ENDCSONengNBIdentificationExtIEsIEContainer []ENDCSONengNBIdentificationExtIEsIEField

// DeactivateTraceIEValueERABIEContainerListValueCodec is the concrete ValueCodec[DeactivateTraceIEValueERABIEContainerList].
type DeactivateTraceIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DeactivateTraceIEValueERABIEContainerList, error)
	encode  func(DeactivateTraceIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DeactivateTraceIEValueERABIEContainerList, aper.DecodeState) (DeactivateTraceIEValueERABIEContainerList, aper.Snapshot)
	compare func(DeactivateTraceIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DeactivateTraceIEValueERABIEContainerListValueCodec) New(value DeactivateTraceIEValueERABIEContainerList) (DeactivateTraceIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DeactivateTraceIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DeactivateTraceIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DeactivateTraceIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DeactivateTraceIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DeactivateTraceIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DeactivateTraceIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DeactivateTraceIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DeactivateTraceIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DeactivateTraceIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DeactivateTraceIEValueERABIEContainerListValueCodec) EncodeAPER(value DeactivateTraceIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DeactivateTraceIEValueERABIEContainerListValueCodec) encodeBudgetValue(value DeactivateTraceIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DeactivateTraceIEValueERABIEContainerListValueCodec) encodeChanged(value DeactivateTraceIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DeactivateTraceIEValueERABIEContainerList is E-RAB-IE-ContainerList {{DeactivateTraceIEs}} of TS 36.413: a list of information element fields.
type DeactivateTraceIEValueERABIEContainerList []DeactivateTraceIEValueProtocolIESingleContainer

// DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec is the concrete ValueCodec[DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList].
type DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, error)
	encode  func(DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot)
	compare func(DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) New(value DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList) (DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) EncodeAPER(value DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) encodeBudgetValue(value DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) encodeChanged(value DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList is E-RAB-IE-ContainerList {{DownlinkNonUEAssociatedLPPaTransport-IEs}} of TS 36.413: a list of information element fields.
type DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList []DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer

// DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec is the concrete ValueCodec[DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList].
type DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, error)
	encode  func(DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot)
	compare func(DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) New(value DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList) (DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) EncodeAPER(value DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) encodeBudgetValue(value DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) encodeChanged(value DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList is E-RAB-IE-ContainerList {{DownlinkUEAssociatedLPPaTransport-IEs}} of TS 36.413: a list of information element fields.
type DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList []DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer

// CellBasedQMCExtIEsExtFieldValueCodec is the concrete ValueCodec[CellBasedQMCExtIEsExtField].
type CellBasedQMCExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s08.CellBasedQMCExtIEsExtField, error)
	encode  func(s08.CellBasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s08.CellBasedQMCExtIEsExtField, aper.DecodeState) (s08.CellBasedQMCExtIEsExtField, aper.Snapshot)
	compare func(s08.CellBasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedQMCExtIEsExtFieldValueCodec) New(value s08.CellBasedQMCExtIEsExtField) (CellBasedQMCExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CellBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedQMCExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedQMCExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedQMCExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedQMCExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedQMCExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedQMCExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedQMCExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedQMCExtIEsExtFieldValueCodec) EncodeAPER(value CellBasedQMCExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedQMCExtIEsExtFieldValueCodec) encodeBudgetValue(value s08.CellBasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedQMCExtIEsExtFieldValueCodec) encodeChanged(value s08.CellBasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDBroadcastItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CellIDBroadcastItemExtIEsExtField].
type CellIDBroadcastItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDBroadcastItemExtIEsExtField, error)
	encode  func(CellIDBroadcastItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDBroadcastItemExtIEsExtField, aper.DecodeState) (CellIDBroadcastItemExtIEsExtField, aper.Snapshot)
	compare func(CellIDBroadcastItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDBroadcastItemExtIEsExtFieldValueCodec) New(value CellIDBroadcastItemExtIEsExtField) (CellIDBroadcastItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CellIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDBroadcastItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDBroadcastItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDBroadcastItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDBroadcastItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDBroadcastItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDBroadcastItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDBroadcastItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDBroadcastItemExtIEsExtFieldValueCodec) EncodeAPER(value CellIDBroadcastItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellIDBroadcastItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CellIDBroadcastItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDBroadcastItemExtIEsExtFieldValueCodec) encodeChanged(value CellIDBroadcastItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDCancelledItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CellIDCancelledItemExtIEsExtField].
type CellIDCancelledItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDCancelledItemExtIEsExtField, error)
	encode  func(CellIDCancelledItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDCancelledItemExtIEsExtField, aper.DecodeState) (CellIDCancelledItemExtIEsExtField, aper.Snapshot)
	compare func(CellIDCancelledItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDCancelledItemExtIEsExtFieldValueCodec) New(value CellIDCancelledItemExtIEsExtField) (CellIDCancelledItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CellIDCancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDCancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDCancelledItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDCancelledItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDCancelledItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDCancelledItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDCancelledItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDCancelledItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDCancelledItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDCancelledItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDCancelledItemExtIEsExtFieldValueCodec) EncodeAPER(value CellIDCancelledItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellIDCancelledItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CellIDCancelledItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDCancelledItemExtIEsExtFieldValueCodec) encodeChanged(value CellIDCancelledItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec is the concrete ValueCodec[CellIdentifierAndCELevelForCECapableUEsExtIEsExtField].
type CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, error)
	encode  func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.Snapshot)
	compare func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) New(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtField) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) EncodeAPER(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) encodeBudgetValue(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) encodeChanged(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTypeExtIEsExtFieldValueCodec is the concrete ValueCodec[CellTypeExtIEsExtField].
type CellTypeExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTypeExtIEsExtField, error)
	encode  func(CellTypeExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTypeExtIEsExtField, aper.DecodeState) (CellTypeExtIEsExtField, aper.Snapshot)
	compare func(CellTypeExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTypeExtIEsExtFieldValueCodec) New(value CellTypeExtIEsExtField) (CellTypeExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CellTypeExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTypeExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTypeExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTypeExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTypeExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTypeExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTypeExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTypeExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTypeExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTypeExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTypeExtIEsExtFieldValueCodec) EncodeAPER(value CellTypeExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellTypeExtIEsExtFieldValueCodec) encodeBudgetValue(value CellTypeExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTypeExtIEsExtFieldValueCodec) encodeChanged(value CellTypeExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinEAIItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CompletedCellinEAIItemExtIEsExtField].
type CompletedCellinEAIItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtField, error)
	encode  func(CompletedCellinEAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinEAIItemExtIEsExtField, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtField, aper.Snapshot)
	compare func(CompletedCellinEAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinEAIItemExtIEsExtFieldValueCodec) New(value CompletedCellinEAIItemExtIEsExtField) (CompletedCellinEAIItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinEAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinEAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinEAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinEAIItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinEAIItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinEAIItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinEAIItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinEAIItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinEAIItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinEAIItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinEAIItemExtIEsExtFieldValueCodec) EncodeAPER(value CompletedCellinEAIItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CompletedCellinEAIItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CompletedCellinEAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinEAIItemExtIEsExtFieldValueCodec) encodeChanged(value CompletedCellinEAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinTAIItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CompletedCellinTAIItemExtIEsExtField].
type CompletedCellinTAIItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtField, error)
	encode  func(CompletedCellinTAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinTAIItemExtIEsExtField, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtField, aper.Snapshot)
	compare func(CompletedCellinTAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinTAIItemExtIEsExtFieldValueCodec) New(value CompletedCellinTAIItemExtIEsExtField) (CompletedCellinTAIItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinTAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinTAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinTAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinTAIItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinTAIItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinTAIItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinTAIItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinTAIItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinTAIItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinTAIItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinTAIItemExtIEsExtFieldValueCodec) EncodeAPER(value CompletedCellinTAIItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CompletedCellinTAIItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CompletedCellinTAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinTAIItemExtIEsExtFieldValueCodec) encodeChanged(value CompletedCellinTAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectedengNBItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ConnectedengNBItemExtIEsExtField].
type ConnectedengNBItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectedengNBItemExtIEsExtField, error)
	encode  func(ConnectedengNBItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectedengNBItemExtIEsExtField, aper.DecodeState) (ConnectedengNBItemExtIEsExtField, aper.Snapshot)
	compare func(ConnectedengNBItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectedengNBItemExtIEsExtFieldValueCodec) New(value ConnectedengNBItemExtIEsExtField) (ConnectedengNBItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ConnectedengNBItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectedengNBItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectedengNBItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectedengNBItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectedengNBItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectedengNBItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectedengNBItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectedengNBItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectedengNBItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectedengNBItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectedengNBItemExtIEsExtFieldValueCodec) EncodeAPER(value ConnectedengNBItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ConnectedengNBItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ConnectedengNBItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectedengNBItemExtIEsExtFieldValueCodec) encodeChanged(value ConnectedengNBItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ContextatSourceExtIEsExtFieldValueCodec is the concrete ValueCodec[ContextatSourceExtIEsExtField].
type ContextatSourceExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ContextatSourceExtIEsExtField, error)
	encode  func(ContextatSourceExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ContextatSourceExtIEsExtField, aper.DecodeState) (ContextatSourceExtIEsExtField, aper.Snapshot)
	compare func(ContextatSourceExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ContextatSourceExtIEsExtFieldValueCodec) New(value ContextatSourceExtIEsExtField) (ContextatSourceExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ContextatSourceExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ContextatSourceExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ContextatSourceExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ContextatSourceExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ContextatSourceExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ContextatSourceExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ContextatSourceExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ContextatSourceExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ContextatSourceExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ContextatSourceExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ContextatSourceExtIEsExtFieldValueCodec) EncodeAPER(value ContextatSourceExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ContextatSourceExtIEsExtFieldValueCodec) encodeBudgetValue(value ContextatSourceExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ContextatSourceExtIEsExtFieldValueCodec) encodeChanged(value ContextatSourceExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsExtIEsExtFieldValueCodec is the concrete ValueCodec[CriticalityDiagnosticsExtIEsExtField].
type CriticalityDiagnosticsExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtField, error)
	encode  func(CriticalityDiagnosticsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsExtIEsExtField, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtField, aper.Snapshot)
	compare func(CriticalityDiagnosticsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsExtIEsExtFieldValueCodec) New(value CriticalityDiagnosticsExtIEsExtField) (CriticalityDiagnosticsExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsExtIEsExtFieldValueCodec) EncodeAPER(value CriticalityDiagnosticsExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CriticalityDiagnosticsExtIEsExtFieldValueCodec) encodeBudgetValue(value CriticalityDiagnosticsExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsExtIEsExtFieldValueCodec) encodeChanged(value CriticalityDiagnosticsExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEItemExtIEsExtField].
type CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtField, error)
	encode  func(CriticalityDiagnosticsIEItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsIEItemExtIEsExtField, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtField, aper.Snapshot)
	compare func(CriticalityDiagnosticsIEItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) New(value CriticalityDiagnosticsIEItemExtIEsExtField) (CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) EncodeAPER(value CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CriticalityDiagnosticsIEItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) encodeChanged(value CriticalityDiagnosticsIEItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSRequestInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[DAPSRequestInfoExtIEsExtField].
type DAPSRequestInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSRequestInfoExtIEsExtField, error)
	encode  func(DAPSRequestInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSRequestInfoExtIEsExtField, aper.DecodeState) (DAPSRequestInfoExtIEsExtField, aper.Snapshot)
	compare func(DAPSRequestInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSRequestInfoExtIEsExtFieldValueCodec) New(value DAPSRequestInfoExtIEsExtField) (DAPSRequestInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return DAPSRequestInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSRequestInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSRequestInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSRequestInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSRequestInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSRequestInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSRequestInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSRequestInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSRequestInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSRequestInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSRequestInfoExtIEsExtFieldValueCodec) EncodeAPER(value DAPSRequestInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DAPSRequestInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value DAPSRequestInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSRequestInfoExtIEsExtFieldValueCodec) encodeChanged(value DAPSRequestInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[DAPSResponseInfoExtIEsExtField].
type DAPSResponseInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoExtIEsExtField, error)
	encode  func(DAPSResponseInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoExtIEsExtField, aper.DecodeState) (DAPSResponseInfoExtIEsExtField, aper.Snapshot)
	compare func(DAPSResponseInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoExtIEsExtFieldValueCodec) New(value DAPSResponseInfoExtIEsExtField) (DAPSResponseInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoExtIEsExtFieldValueCodec) EncodeAPER(value DAPSResponseInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DAPSResponseInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value DAPSResponseInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoExtIEsExtFieldValueCodec) encodeChanged(value DAPSResponseInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoItemExtIEsExtFieldValueCodec is the concrete ValueCodec[DAPSResponseInfoItemExtIEsExtField].
type DAPSResponseInfoItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtField, error)
	encode  func(DAPSResponseInfoItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoItemExtIEsExtField, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtField, aper.Snapshot)
	compare func(DAPSResponseInfoItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoItemExtIEsExtFieldValueCodec) New(value DAPSResponseInfoItemExtIEsExtField) (DAPSResponseInfoItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoItemExtIEsExtFieldValueCodec) EncodeAPER(value DAPSResponseInfoItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DAPSResponseInfoItemExtIEsExtFieldValueCodec) encodeBudgetValue(value DAPSResponseInfoItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoItemExtIEsExtFieldValueCodec) encodeChanged(value DAPSResponseInfoItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DLCPSecurityInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[DLCPSecurityInformationExtIEsExtField].
type DLCPSecurityInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DLCPSecurityInformationExtIEsExtField, error)
	encode  func(DLCPSecurityInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DLCPSecurityInformationExtIEsExtField, aper.DecodeState) (DLCPSecurityInformationExtIEsExtField, aper.Snapshot)
	compare func(DLCPSecurityInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DLCPSecurityInformationExtIEsExtFieldValueCodec) New(value DLCPSecurityInformationExtIEsExtField) (DLCPSecurityInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return DLCPSecurityInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DLCPSecurityInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DLCPSecurityInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DLCPSecurityInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DLCPSecurityInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DLCPSecurityInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DLCPSecurityInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DLCPSecurityInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DLCPSecurityInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DLCPSecurityInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DLCPSecurityInformationExtIEsExtFieldValueCodec) EncodeAPER(value DLCPSecurityInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DLCPSecurityInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value DLCPSecurityInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DLCPSecurityInformationExtIEsExtFieldValueCodec) encodeChanged(value DLCPSecurityInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec is the concrete ValueCodec[ENBStatusTransferTransparentContainerExtIEsExtField].
type ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtField, error)
	encode  func(ENBStatusTransferTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferTransparentContainerExtIEsExtField, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot)
	compare func(ENBStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) New(value ENBStatusTransferTransparentContainerExtIEsExtField) (ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) EncodeAPER(value ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) encodeBudgetValue(value ENBStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) encodeChanged(value ENBStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBX2ExtTLAExtIEsExtFieldValueCodec is the concrete ValueCodec[ENBX2ExtTLAExtIEsExtField].
type ENBX2ExtTLAExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBX2ExtTLAExtIEsExtField, error)
	encode  func(ENBX2ExtTLAExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBX2ExtTLAExtIEsExtField, aper.DecodeState) (ENBX2ExtTLAExtIEsExtField, aper.Snapshot)
	compare func(ENBX2ExtTLAExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBX2ExtTLAExtIEsExtFieldValueCodec) New(value ENBX2ExtTLAExtIEsExtField) (ENBX2ExtTLAExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENBX2ExtTLAExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBX2ExtTLAExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBX2ExtTLAExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBX2ExtTLAExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBX2ExtTLAExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBX2ExtTLAExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBX2ExtTLAExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBX2ExtTLAExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBX2ExtTLAExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBX2ExtTLAExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBX2ExtTLAExtIEsExtFieldValueCodec) EncodeAPER(value ENBX2ExtTLAExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBX2ExtTLAExtIEsExtFieldValueCodec) encodeBudgetValue(value ENBX2ExtTLAExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBX2ExtTLAExtIEsExtFieldValueCodec) encodeChanged(value ENBX2ExtTLAExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONConfigurationTransferExtIEsExtFieldValueCodec is the concrete ValueCodec[ENDCSONConfigurationTransferExtIEsExtField].
type ENDCSONConfigurationTransferExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtField, error)
	encode  func(ENDCSONConfigurationTransferExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONConfigurationTransferExtIEsExtField, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtField, aper.Snapshot)
	compare func(ENDCSONConfigurationTransferExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) New(value ENDCSONConfigurationTransferExtIEsExtField) (ENDCSONConfigurationTransferExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONConfigurationTransferExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONConfigurationTransferExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) EncodeAPER(value ENDCSONConfigurationTransferExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) encodeBudgetValue(value ENDCSONConfigurationTransferExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) encodeChanged(value ENDCSONConfigurationTransferExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONeNBIdentificationExtIEsExtFieldValueCodec is the concrete ValueCodec[ENDCSONeNBIdentificationExtIEsExtField].
type ENDCSONeNBIdentificationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtField, error)
	encode  func(ENDCSONeNBIdentificationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONeNBIdentificationExtIEsExtField, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtField, aper.Snapshot)
	compare func(ENDCSONeNBIdentificationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) New(value ENDCSONeNBIdentificationExtIEsExtField) (ENDCSONeNBIdentificationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONeNBIdentificationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONeNBIdentificationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) EncodeAPER(value ENDCSONeNBIdentificationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) encodeBudgetValue(value ENDCSONeNBIdentificationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) encodeChanged(value ENDCSONeNBIdentificationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONengNBIdentificationExtIEsExtFieldValueCodec is the concrete ValueCodec[ENDCSONengNBIdentificationExtIEsExtField].
type ENDCSONengNBIdentificationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtField, error)
	encode  func(ENDCSONengNBIdentificationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONengNBIdentificationExtIEsExtField, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtField, aper.Snapshot)
	compare func(ENDCSONengNBIdentificationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) New(value ENDCSONengNBIdentificationExtIEsExtField) (ENDCSONengNBIdentificationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONengNBIdentificationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONengNBIdentificationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) EncodeAPER(value ENDCSONengNBIdentificationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) encodeBudgetValue(value ENDCSONengNBIdentificationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) encodeChanged(value ENDCSONengNBIdentificationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCTransferTypeReplyExtIEsExtFieldValueCodec is the concrete ValueCodec[ENDCTransferTypeReplyExtIEsExtField].
type ENDCTransferTypeReplyExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtField, error)
	encode  func(ENDCTransferTypeReplyExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCTransferTypeReplyExtIEsExtField, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtField, aper.Snapshot)
	compare func(ENDCTransferTypeReplyExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCTransferTypeReplyExtIEsExtFieldValueCodec) New(value ENDCTransferTypeReplyExtIEsExtField) (ENDCTransferTypeReplyExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCTransferTypeReplyExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCTransferTypeReplyExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCTransferTypeReplyExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCTransferTypeReplyExtIEsExtFieldValueCodec) EncodeAPER(value ENDCTransferTypeReplyExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCTransferTypeReplyExtIEsExtFieldValueCodec) encodeBudgetValue(value ENDCTransferTypeReplyExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCTransferTypeReplyExtIEsExtFieldValueCodec) encodeChanged(value ENDCTransferTypeReplyExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDBroadcastItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CellIDBroadcastItemExtIEsExtContainer].
type CellIDBroadcastItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDBroadcastItemExtIEsExtContainer, error)
	encode  func(CellIDBroadcastItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDBroadcastItemExtIEsExtContainer, aper.DecodeState) (CellIDBroadcastItemExtIEsExtContainer, aper.Snapshot)
	compare func(CellIDBroadcastItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDBroadcastItemExtIEsExtContainerValueCodec) New(value CellIDBroadcastItemExtIEsExtContainer) (CellIDBroadcastItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CellIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDBroadcastItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDBroadcastItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDBroadcastItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDBroadcastItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDBroadcastItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDBroadcastItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDBroadcastItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDBroadcastItemExtIEsExtContainerValueCodec) EncodeAPER(value CellIDBroadcastItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellIDBroadcastItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CellIDBroadcastItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDBroadcastItemExtIEsExtContainerValueCodec) encodeChanged(value CellIDBroadcastItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDCancelledItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CellIDCancelledItemExtIEsExtContainer].
type CellIDCancelledItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDCancelledItemExtIEsExtContainer, error)
	encode  func(CellIDCancelledItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDCancelledItemExtIEsExtContainer, aper.DecodeState) (CellIDCancelledItemExtIEsExtContainer, aper.Snapshot)
	compare func(CellIDCancelledItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDCancelledItemExtIEsExtContainerValueCodec) New(value CellIDCancelledItemExtIEsExtContainer) (CellIDCancelledItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CellIDCancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDCancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDCancelledItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDCancelledItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDCancelledItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDCancelledItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDCancelledItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDCancelledItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDCancelledItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDCancelledItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDCancelledItemExtIEsExtContainerValueCodec) EncodeAPER(value CellIDCancelledItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellIDCancelledItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CellIDCancelledItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDCancelledItemExtIEsExtContainerValueCodec) encodeChanged(value CellIDCancelledItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec is the concrete ValueCodec[CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer].
type CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, error)
	encode  func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.Snapshot)
	compare func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) New(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) EncodeAPER(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) encodeBudgetValue(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) encodeChanged(value CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTypeExtIEsExtContainerValueCodec is the concrete ValueCodec[CellTypeExtIEsExtContainer].
type CellTypeExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTypeExtIEsExtContainer, error)
	encode  func(CellTypeExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTypeExtIEsExtContainer, aper.DecodeState) (CellTypeExtIEsExtContainer, aper.Snapshot)
	compare func(CellTypeExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTypeExtIEsExtContainerValueCodec) New(value CellTypeExtIEsExtContainer) (CellTypeExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CellTypeExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTypeExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTypeExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTypeExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTypeExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTypeExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTypeExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTypeExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTypeExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTypeExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTypeExtIEsExtContainerValueCodec) EncodeAPER(value CellTypeExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellTypeExtIEsExtContainerValueCodec) encodeBudgetValue(value CellTypeExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTypeExtIEsExtContainerValueCodec) encodeChanged(value CellTypeExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinEAIItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CompletedCellinEAIItemExtIEsExtContainer].
type CompletedCellinEAIItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtContainer, error)
	encode  func(CompletedCellinEAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinEAIItemExtIEsExtContainer, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtContainer, aper.Snapshot)
	compare func(CompletedCellinEAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinEAIItemExtIEsExtContainerValueCodec) New(value CompletedCellinEAIItemExtIEsExtContainer) (CompletedCellinEAIItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinEAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinEAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinEAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinEAIItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinEAIItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinEAIItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinEAIItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinEAIItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinEAIItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinEAIItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinEAIItemExtIEsExtContainerValueCodec) EncodeAPER(value CompletedCellinEAIItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CompletedCellinEAIItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CompletedCellinEAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinEAIItemExtIEsExtContainerValueCodec) encodeChanged(value CompletedCellinEAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinTAIItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CompletedCellinTAIItemExtIEsExtContainer].
type CompletedCellinTAIItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtContainer, error)
	encode  func(CompletedCellinTAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinTAIItemExtIEsExtContainer, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtContainer, aper.Snapshot)
	compare func(CompletedCellinTAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinTAIItemExtIEsExtContainerValueCodec) New(value CompletedCellinTAIItemExtIEsExtContainer) (CompletedCellinTAIItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinTAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinTAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinTAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinTAIItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinTAIItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinTAIItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinTAIItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinTAIItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinTAIItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinTAIItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinTAIItemExtIEsExtContainerValueCodec) EncodeAPER(value CompletedCellinTAIItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CompletedCellinTAIItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CompletedCellinTAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinTAIItemExtIEsExtContainerValueCodec) encodeChanged(value CompletedCellinTAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectedengNBItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ConnectedengNBItemExtIEsExtContainer].
type ConnectedengNBItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectedengNBItemExtIEsExtContainer, error)
	encode  func(ConnectedengNBItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectedengNBItemExtIEsExtContainer, aper.DecodeState) (ConnectedengNBItemExtIEsExtContainer, aper.Snapshot)
	compare func(ConnectedengNBItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectedengNBItemExtIEsExtContainerValueCodec) New(value ConnectedengNBItemExtIEsExtContainer) (ConnectedengNBItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ConnectedengNBItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectedengNBItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectedengNBItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectedengNBItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectedengNBItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectedengNBItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectedengNBItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectedengNBItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectedengNBItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectedengNBItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectedengNBItemExtIEsExtContainerValueCodec) EncodeAPER(value ConnectedengNBItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ConnectedengNBItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ConnectedengNBItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectedengNBItemExtIEsExtContainerValueCodec) encodeChanged(value ConnectedengNBItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ContextatSourceExtIEsExtContainerValueCodec is the concrete ValueCodec[ContextatSourceExtIEsExtContainer].
type ContextatSourceExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ContextatSourceExtIEsExtContainer, error)
	encode  func(ContextatSourceExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ContextatSourceExtIEsExtContainer, aper.DecodeState) (ContextatSourceExtIEsExtContainer, aper.Snapshot)
	compare func(ContextatSourceExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ContextatSourceExtIEsExtContainerValueCodec) New(value ContextatSourceExtIEsExtContainer) (ContextatSourceExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ContextatSourceExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ContextatSourceExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ContextatSourceExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ContextatSourceExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ContextatSourceExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ContextatSourceExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ContextatSourceExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ContextatSourceExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ContextatSourceExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ContextatSourceExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ContextatSourceExtIEsExtContainerValueCodec) EncodeAPER(value ContextatSourceExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ContextatSourceExtIEsExtContainerValueCodec) encodeBudgetValue(value ContextatSourceExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ContextatSourceExtIEsExtContainerValueCodec) encodeChanged(value ContextatSourceExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsExtIEsExtContainerValueCodec is the concrete ValueCodec[CriticalityDiagnosticsExtIEsExtContainer].
type CriticalityDiagnosticsExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtContainer, error)
	encode  func(CriticalityDiagnosticsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsExtIEsExtContainer, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtContainer, aper.Snapshot)
	compare func(CriticalityDiagnosticsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsExtIEsExtContainerValueCodec) New(value CriticalityDiagnosticsExtIEsExtContainer) (CriticalityDiagnosticsExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsExtIEsExtContainerValueCodec) EncodeAPER(value CriticalityDiagnosticsExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CriticalityDiagnosticsExtIEsExtContainerValueCodec) encodeBudgetValue(value CriticalityDiagnosticsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsExtIEsExtContainerValueCodec) encodeChanged(value CriticalityDiagnosticsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEItemExtIEsExtContainer].
type CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtContainer, error)
	encode  func(CriticalityDiagnosticsIEItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.Snapshot)
	compare func(CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) New(value CriticalityDiagnosticsIEItemExtIEsExtContainer) (CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) EncodeAPER(value CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CriticalityDiagnosticsIEItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) encodeChanged(value CriticalityDiagnosticsIEItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSRequestInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[DAPSRequestInfoExtIEsExtContainer].
type DAPSRequestInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSRequestInfoExtIEsExtContainer, error)
	encode  func(DAPSRequestInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSRequestInfoExtIEsExtContainer, aper.DecodeState) (DAPSRequestInfoExtIEsExtContainer, aper.Snapshot)
	compare func(DAPSRequestInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSRequestInfoExtIEsExtContainerValueCodec) New(value DAPSRequestInfoExtIEsExtContainer) (DAPSRequestInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return DAPSRequestInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSRequestInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSRequestInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSRequestInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSRequestInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSRequestInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSRequestInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSRequestInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSRequestInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSRequestInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSRequestInfoExtIEsExtContainerValueCodec) EncodeAPER(value DAPSRequestInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DAPSRequestInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value DAPSRequestInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSRequestInfoExtIEsExtContainerValueCodec) encodeChanged(value DAPSRequestInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[DAPSResponseInfoExtIEsExtContainer].
type DAPSResponseInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoExtIEsExtContainer, error)
	encode  func(DAPSResponseInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoExtIEsExtContainer, aper.DecodeState) (DAPSResponseInfoExtIEsExtContainer, aper.Snapshot)
	compare func(DAPSResponseInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoExtIEsExtContainerValueCodec) New(value DAPSResponseInfoExtIEsExtContainer) (DAPSResponseInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoExtIEsExtContainerValueCodec) EncodeAPER(value DAPSResponseInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DAPSResponseInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value DAPSResponseInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoExtIEsExtContainerValueCodec) encodeChanged(value DAPSResponseInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoItemExtIEsExtContainerValueCodec is the concrete ValueCodec[DAPSResponseInfoItemExtIEsExtContainer].
type DAPSResponseInfoItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtContainer, error)
	encode  func(DAPSResponseInfoItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoItemExtIEsExtContainer, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtContainer, aper.Snapshot)
	compare func(DAPSResponseInfoItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoItemExtIEsExtContainerValueCodec) New(value DAPSResponseInfoItemExtIEsExtContainer) (DAPSResponseInfoItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoItemExtIEsExtContainerValueCodec) EncodeAPER(value DAPSResponseInfoItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DAPSResponseInfoItemExtIEsExtContainerValueCodec) encodeBudgetValue(value DAPSResponseInfoItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoItemExtIEsExtContainerValueCodec) encodeChanged(value DAPSResponseInfoItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DLCPSecurityInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[DLCPSecurityInformationExtIEsExtContainer].
type DLCPSecurityInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DLCPSecurityInformationExtIEsExtContainer, error)
	encode  func(DLCPSecurityInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DLCPSecurityInformationExtIEsExtContainer, aper.DecodeState) (DLCPSecurityInformationExtIEsExtContainer, aper.Snapshot)
	compare func(DLCPSecurityInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DLCPSecurityInformationExtIEsExtContainerValueCodec) New(value DLCPSecurityInformationExtIEsExtContainer) (DLCPSecurityInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return DLCPSecurityInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DLCPSecurityInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DLCPSecurityInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DLCPSecurityInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DLCPSecurityInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DLCPSecurityInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DLCPSecurityInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DLCPSecurityInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DLCPSecurityInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DLCPSecurityInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DLCPSecurityInformationExtIEsExtContainerValueCodec) EncodeAPER(value DLCPSecurityInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DLCPSecurityInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value DLCPSecurityInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DLCPSecurityInformationExtIEsExtContainerValueCodec) encodeChanged(value DLCPSecurityInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec is the concrete ValueCodec[ENBStatusTransferTransparentContainerExtIEsExtContainer].
type ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtContainer, error)
	encode  func(ENBStatusTransferTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot)
	compare func(ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) New(value ENBStatusTransferTransparentContainerExtIEsExtContainer) (ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) EncodeAPER(value ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) encodeBudgetValue(value ENBStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) encodeChanged(value ENBStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBX2ExtTLAExtIEsExtContainerValueCodec is the concrete ValueCodec[ENBX2ExtTLAExtIEsExtContainer].
type ENBX2ExtTLAExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBX2ExtTLAExtIEsExtContainer, error)
	encode  func(ENBX2ExtTLAExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBX2ExtTLAExtIEsExtContainer, aper.DecodeState) (ENBX2ExtTLAExtIEsExtContainer, aper.Snapshot)
	compare func(ENBX2ExtTLAExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBX2ExtTLAExtIEsExtContainerValueCodec) New(value ENBX2ExtTLAExtIEsExtContainer) (ENBX2ExtTLAExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENBX2ExtTLAExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBX2ExtTLAExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBX2ExtTLAExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBX2ExtTLAExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBX2ExtTLAExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBX2ExtTLAExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBX2ExtTLAExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBX2ExtTLAExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBX2ExtTLAExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBX2ExtTLAExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBX2ExtTLAExtIEsExtContainerValueCodec) EncodeAPER(value ENBX2ExtTLAExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBX2ExtTLAExtIEsExtContainerValueCodec) encodeBudgetValue(value ENBX2ExtTLAExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBX2ExtTLAExtIEsExtContainerValueCodec) encodeChanged(value ENBX2ExtTLAExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONConfigurationTransferExtIEsExtContainerValueCodec is the concrete ValueCodec[ENDCSONConfigurationTransferExtIEsExtContainer].
type ENDCSONConfigurationTransferExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtContainer, error)
	encode  func(ENDCSONConfigurationTransferExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONConfigurationTransferExtIEsExtContainer, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtContainer, aper.Snapshot)
	compare func(ENDCSONConfigurationTransferExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) New(value ENDCSONConfigurationTransferExtIEsExtContainer) (ENDCSONConfigurationTransferExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONConfigurationTransferExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONConfigurationTransferExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) EncodeAPER(value ENDCSONConfigurationTransferExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) encodeBudgetValue(value ENDCSONConfigurationTransferExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) encodeChanged(value ENDCSONConfigurationTransferExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONeNBIdentificationExtIEsExtContainerValueCodec is the concrete ValueCodec[ENDCSONeNBIdentificationExtIEsExtContainer].
type ENDCSONeNBIdentificationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtContainer, error)
	encode  func(ENDCSONeNBIdentificationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONeNBIdentificationExtIEsExtContainer, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtContainer, aper.Snapshot)
	compare func(ENDCSONeNBIdentificationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) New(value ENDCSONeNBIdentificationExtIEsExtContainer) (ENDCSONeNBIdentificationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONeNBIdentificationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONeNBIdentificationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) EncodeAPER(value ENDCSONeNBIdentificationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) encodeBudgetValue(value ENDCSONeNBIdentificationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) encodeChanged(value ENDCSONeNBIdentificationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONengNBIdentificationExtIEsExtContainerValueCodec is the concrete ValueCodec[ENDCSONengNBIdentificationExtIEsExtContainer].
type ENDCSONengNBIdentificationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtContainer, error)
	encode  func(ENDCSONengNBIdentificationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONengNBIdentificationExtIEsExtContainer, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtContainer, aper.Snapshot)
	compare func(ENDCSONengNBIdentificationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) New(value ENDCSONengNBIdentificationExtIEsExtContainer) (ENDCSONengNBIdentificationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONengNBIdentificationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONengNBIdentificationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) EncodeAPER(value ENDCSONengNBIdentificationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) encodeBudgetValue(value ENDCSONengNBIdentificationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) encodeChanged(value ENDCSONengNBIdentificationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCTransferTypeReplyExtIEsExtContainerValueCodec is the concrete ValueCodec[ENDCTransferTypeReplyExtIEsExtContainer].
type ENDCTransferTypeReplyExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtContainer, error)
	encode  func(ENDCTransferTypeReplyExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCTransferTypeReplyExtIEsExtContainer, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtContainer, aper.Snapshot)
	compare func(ENDCTransferTypeReplyExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCTransferTypeReplyExtIEsExtContainerValueCodec) New(value ENDCTransferTypeReplyExtIEsExtContainer) (ENDCTransferTypeReplyExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCTransferTypeReplyExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCTransferTypeReplyExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCTransferTypeReplyExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCTransferTypeReplyExtIEsExtContainerValueCodec) EncodeAPER(value ENDCTransferTypeReplyExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENDCTransferTypeReplyExtIEsExtContainerValueCodec) encodeBudgetValue(value ENDCTransferTypeReplyExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCTransferTypeReplyExtIEsExtContainerValueCodec) encodeChanged(value ENDCTransferTypeReplyExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DeactivateTraceIEFieldValueCodec is the concrete ValueCodec[DeactivateTraceIEField].
type DeactivateTraceIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DeactivateTraceIEField, error)
	encode  func(DeactivateTraceIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DeactivateTraceIEField, aper.DecodeState) (DeactivateTraceIEField, aper.Snapshot)
	compare func(DeactivateTraceIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DeactivateTraceIEFieldValueCodec) New(value DeactivateTraceIEField) (DeactivateTraceIEFieldAPERValue, error) {
	if c.encode == nil {
		return DeactivateTraceIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DeactivateTraceIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DeactivateTraceIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DeactivateTraceIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DeactivateTraceIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DeactivateTraceIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DeactivateTraceIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DeactivateTraceIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DeactivateTraceIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DeactivateTraceIEFieldValueCodec) EncodeAPER(value DeactivateTraceIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DeactivateTraceIEFieldValueCodec) encodeBudgetValue(value DeactivateTraceIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DeactivateTraceIEFieldValueCodec) encodeChanged(value DeactivateTraceIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec is the concrete ValueCodec[DownlinkNonUEAssociatedLPPaTransportIEField].
type DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEField, error)
	encode  func(DownlinkNonUEAssociatedLPPaTransportIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNonUEAssociatedLPPaTransportIEField, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot)
	compare func(DownlinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) New(value DownlinkNonUEAssociatedLPPaTransportIEField) (DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue, error) {
	if c.encode == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) EncodeAPER(value DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) encodeBudgetValue(value DownlinkNonUEAssociatedLPPaTransportIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) encodeChanged(value DownlinkNonUEAssociatedLPPaTransportIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkUEAssociatedLPPaTransportIEFieldValueCodec is the concrete ValueCodec[DownlinkUEAssociatedLPPaTransportIEField].
type DownlinkUEAssociatedLPPaTransportIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEField, error)
	encode  func(DownlinkUEAssociatedLPPaTransportIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkUEAssociatedLPPaTransportIEField, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEField, aper.Snapshot)
	compare func(DownlinkUEAssociatedLPPaTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) New(value DownlinkUEAssociatedLPPaTransportIEField) (DownlinkUEAssociatedLPPaTransportIEFieldAPERValue, error) {
	if c.encode == nil {
		return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkUEAssociatedLPPaTransportIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkUEAssociatedLPPaTransportIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) EncodeAPER(value DownlinkUEAssociatedLPPaTransportIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) encodeBudgetValue(value DownlinkUEAssociatedLPPaTransportIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) encodeChanged(value DownlinkUEAssociatedLPPaTransportIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DeactivateTraceIEContainerValueCodec is the concrete ValueCodec[DeactivateTraceIEContainer].
type DeactivateTraceIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DeactivateTraceIEContainer, error)
	encode  func(DeactivateTraceIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DeactivateTraceIEContainer, aper.DecodeState) (DeactivateTraceIEContainer, aper.Snapshot)
	compare func(DeactivateTraceIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DeactivateTraceIEContainerValueCodec) New(value DeactivateTraceIEContainer) (DeactivateTraceIEContainerAPERValue, error) {
	if c.encode == nil {
		return DeactivateTraceIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DeactivateTraceIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DeactivateTraceIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DeactivateTraceIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DeactivateTraceIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DeactivateTraceIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DeactivateTraceIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DeactivateTraceIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DeactivateTraceIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DeactivateTraceIEContainerValueCodec) EncodeAPER(value DeactivateTraceIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DeactivateTraceIEContainerValueCodec) encodeBudgetValue(value DeactivateTraceIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DeactivateTraceIEContainerValueCodec) encodeChanged(value DeactivateTraceIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec is the concrete ValueCodec[DownlinkNonUEAssociatedLPPaTransportIEContainer].
type DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEContainer, error)
	encode  func(DownlinkNonUEAssociatedLPPaTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot)
	compare func(DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) New(value DownlinkNonUEAssociatedLPPaTransportIEContainer) (DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue, error) {
	if c.encode == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) EncodeAPER(value DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) encodeBudgetValue(value DownlinkNonUEAssociatedLPPaTransportIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) encodeChanged(value DownlinkNonUEAssociatedLPPaTransportIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkUEAssociatedLPPaTransportIEContainerValueCodec is the concrete ValueCodec[DownlinkUEAssociatedLPPaTransportIEContainer].
type DownlinkUEAssociatedLPPaTransportIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEContainer, error)
	encode  func(DownlinkUEAssociatedLPPaTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkUEAssociatedLPPaTransportIEContainer, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot)
	compare func(DownlinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) New(value DownlinkUEAssociatedLPPaTransportIEContainer) (DownlinkUEAssociatedLPPaTransportIEContainerAPERValue, error) {
	if c.encode == nil {
		return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkUEAssociatedLPPaTransportIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkUEAssociatedLPPaTransportIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) EncodeAPER(value DownlinkUEAssociatedLPPaTransportIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) encodeBudgetValue(value DownlinkUEAssociatedLPPaTransportIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) encodeChanged(value DownlinkUEAssociatedLPPaTransportIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[DeactivateTraceIEValueProtocolErrorIEContainerList].
type DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DeactivateTraceIEValueProtocolErrorIEContainerList, error)
	encode  func(DeactivateTraceIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DeactivateTraceIEValueProtocolErrorIEContainerList, aper.DecodeState) (DeactivateTraceIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(DeactivateTraceIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) New(value DeactivateTraceIEValueProtocolErrorIEContainerList) (DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value DeactivateTraceIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value DeactivateTraceIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DeactivateTraceIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{DeactivateTraceIEs}} of TS 36.413: a list of information element fields.
type DeactivateTraceIEValueProtocolErrorIEContainerList []DeactivateTraceIEValueProtocolIESingleContainer

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList].
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error)
	encode  func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) New(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{DownlinkNonUEAssociatedLPPaTransport-IEs}} of TS 36.413: a list of information element fields.
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList []DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer

// DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList].
type DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error)
	encode  func(DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) New(value DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList) (DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{DownlinkUEAssociatedLPPaTransport-IEs}} of TS 36.413: a list of information element fields.
type DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList []DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer

// DeactivateTraceIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[DeactivateTraceIEValueProtocolIEContainerList].
type DeactivateTraceIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DeactivateTraceIEValueProtocolIEContainerList, error)
	encode  func(DeactivateTraceIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DeactivateTraceIEValueProtocolIEContainerList, aper.DecodeState) (DeactivateTraceIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(DeactivateTraceIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DeactivateTraceIEValueProtocolIEContainerListValueCodec) New(value DeactivateTraceIEValueProtocolIEContainerList) (DeactivateTraceIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DeactivateTraceIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DeactivateTraceIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DeactivateTraceIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DeactivateTraceIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DeactivateTraceIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DeactivateTraceIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DeactivateTraceIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DeactivateTraceIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DeactivateTraceIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DeactivateTraceIEValueProtocolIEContainerListValueCodec) EncodeAPER(value DeactivateTraceIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DeactivateTraceIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value DeactivateTraceIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DeactivateTraceIEValueProtocolIEContainerListValueCodec) encodeChanged(value DeactivateTraceIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DeactivateTraceIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {DeactivateTraceIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type DeactivateTraceIEValueProtocolIEContainerList []DeactivateTraceIEValueProtocolIESingleContainer

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList].
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error)
	encode  func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) New(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) EncodeAPER(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) encodeChanged(value DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {DownlinkNonUEAssociatedLPPaTransport-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList []DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer

// DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList].
type DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error)
	encode  func(DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) New(value DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList) (DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) EncodeAPER(value DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) encodeChanged(value DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {DownlinkUEAssociatedLPPaTransport-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList []DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer

// DeactivateTraceIEValueERABIEContainerListAPERValue is the concrete APERValue[DeactivateTraceIEValueERABIEContainerList].
type DeactivateTraceIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DeactivateTraceIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DeactivateTraceIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DeactivateTraceIEValueERABIEContainerListAPERValue) WithoutReplay() DeactivateTraceIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DeactivateTraceIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{DeactivateTraceIEs}} of TS 36.413: a single information element field.
type DeactivateTraceIEValueProtocolIESingleContainer = DeactivateTraceIEField

// DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue is the concrete APERValue[DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList].
type DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue) WithoutReplay() DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{DownlinkNonUEAssociatedLPPaTransport-IEs}} of TS 36.413: a single information element field.
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer = DownlinkNonUEAssociatedLPPaTransportIEField

// DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue is the concrete APERValue[DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList].
type DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue) WithoutReplay() DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{DownlinkUEAssociatedLPPaTransport-IEs}} of TS 36.413: a single information element field.
type DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer = DownlinkUEAssociatedLPPaTransportIEField

// CellBasedQMCExtIEsExtFieldAPERValue is the concrete APERValue[CellBasedQMCExtIEsExtField].
type CellBasedQMCExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         s08.CellBasedQMCExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedQMCExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedQMCExtIEsExtFieldAPERValue) WithoutReplay() CellBasedQMCExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDBroadcastItemExtIEsExtFieldAPERValue is the concrete APERValue[CellIDBroadcastItemExtIEsExtField].
type CellIDBroadcastItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellIDBroadcastItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDBroadcastItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDBroadcastItemExtIEsExtFieldAPERValue) WithoutReplay() CellIDBroadcastItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDCancelledItemExtIEsExtFieldAPERValue is the concrete APERValue[CellIDCancelledItemExtIEsExtField].
type CellIDCancelledItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellIDCancelledItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDCancelledItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDCancelledItemExtIEsExtFieldAPERValue) WithoutReplay() CellIDCancelledItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue is the concrete APERValue[CellIdentifierAndCELevelForCECapableUEsExtIEsExtField].
type CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellIdentifierAndCELevelForCECapableUEsExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue) WithoutReplay() CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTypeExtIEsExtFieldAPERValue is the concrete APERValue[CellTypeExtIEsExtField].
type CellTypeExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellTypeExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTypeExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTypeExtIEsExtFieldAPERValue) WithoutReplay() CellTypeExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinEAIItemExtIEsExtFieldAPERValue is the concrete APERValue[CompletedCellinEAIItemExtIEsExtField].
type CompletedCellinEAIItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CompletedCellinEAIItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinEAIItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinEAIItemExtIEsExtFieldAPERValue) WithoutReplay() CompletedCellinEAIItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinTAIItemExtIEsExtFieldAPERValue is the concrete APERValue[CompletedCellinTAIItemExtIEsExtField].
type CompletedCellinTAIItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CompletedCellinTAIItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinTAIItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinTAIItemExtIEsExtFieldAPERValue) WithoutReplay() CompletedCellinTAIItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectedengNBItemExtIEsExtFieldAPERValue is the concrete APERValue[ConnectedengNBItemExtIEsExtField].
type ConnectedengNBItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectedengNBItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectedengNBItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBItemExtIEsExtFieldAPERValue) WithoutReplay() ConnectedengNBItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ContextatSourceExtIEsExtFieldAPERValue is the concrete APERValue[ContextatSourceExtIEsExtField].
type ContextatSourceExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ContextatSourceExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ContextatSourceExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ContextatSourceExtIEsExtFieldAPERValue) WithoutReplay() ContextatSourceExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsExtIEsExtFieldAPERValue is the concrete APERValue[CriticalityDiagnosticsExtIEsExtField].
type CriticalityDiagnosticsExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CriticalityDiagnosticsExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsExtIEsExtFieldAPERValue) WithoutReplay() CriticalityDiagnosticsExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue is the concrete APERValue[CriticalityDiagnosticsIEItemExtIEsExtField].
type CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CriticalityDiagnosticsIEItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue) WithoutReplay() CriticalityDiagnosticsIEItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSRequestInfoExtIEsExtFieldAPERValue is the concrete APERValue[DAPSRequestInfoExtIEsExtField].
type DAPSRequestInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSRequestInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSRequestInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSRequestInfoExtIEsExtFieldAPERValue) WithoutReplay() DAPSRequestInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoExtIEsExtFieldAPERValue is the concrete APERValue[DAPSResponseInfoExtIEsExtField].
type DAPSResponseInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoExtIEsExtFieldAPERValue) WithoutReplay() DAPSResponseInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoItemExtIEsExtFieldAPERValue is the concrete APERValue[DAPSResponseInfoItemExtIEsExtField].
type DAPSResponseInfoItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoItemExtIEsExtFieldAPERValue) WithoutReplay() DAPSResponseInfoItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DLCPSecurityInformationExtIEsExtFieldAPERValue is the concrete APERValue[DLCPSecurityInformationExtIEsExtField].
type DLCPSecurityInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DLCPSecurityInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DLCPSecurityInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DLCPSecurityInformationExtIEsExtFieldAPERValue) WithoutReplay() DLCPSecurityInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue is the concrete APERValue[ENBStatusTransferTransparentContainerExtIEsExtField].
type ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferTransparentContainerExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue) WithoutReplay() ENBStatusTransferTransparentContainerExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBX2ExtTLAExtIEsExtFieldAPERValue is the concrete APERValue[ENBX2ExtTLAExtIEsExtField].
type ENBX2ExtTLAExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBX2ExtTLAExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBX2ExtTLAExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBX2ExtTLAExtIEsExtFieldAPERValue) WithoutReplay() ENBX2ExtTLAExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONConfigurationTransferExtIEsExtFieldAPERValue is the concrete APERValue[ENDCSONConfigurationTransferExtIEsExtField].
type ENDCSONConfigurationTransferExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCSONConfigurationTransferExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONConfigurationTransferExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONConfigurationTransferExtIEsExtFieldAPERValue) WithoutReplay() ENDCSONConfigurationTransferExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONeNBIdentificationExtIEsExtFieldAPERValue is the concrete APERValue[ENDCSONeNBIdentificationExtIEsExtField].
type ENDCSONeNBIdentificationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCSONeNBIdentificationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONeNBIdentificationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONeNBIdentificationExtIEsExtFieldAPERValue) WithoutReplay() ENDCSONeNBIdentificationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONengNBIdentificationExtIEsExtFieldAPERValue is the concrete APERValue[ENDCSONengNBIdentificationExtIEsExtField].
type ENDCSONengNBIdentificationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCSONengNBIdentificationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONengNBIdentificationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONengNBIdentificationExtIEsExtFieldAPERValue) WithoutReplay() ENDCSONengNBIdentificationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCTransferTypeReplyExtIEsExtFieldAPERValue is the concrete APERValue[ENDCTransferTypeReplyExtIEsExtField].
type ENDCTransferTypeReplyExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCTransferTypeReplyExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCTransferTypeReplyExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeReplyExtIEsExtFieldAPERValue) WithoutReplay() ENDCTransferTypeReplyExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDBroadcastItemExtIEsExtContainerAPERValue is the concrete APERValue[CellIDBroadcastItemExtIEsExtContainer].
type CellIDBroadcastItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellIDBroadcastItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDBroadcastItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDBroadcastItemExtIEsExtContainerAPERValue) WithoutReplay() CellIDBroadcastItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDCancelledItemExtIEsExtContainerAPERValue is the concrete APERValue[CellIDCancelledItemExtIEsExtContainer].
type CellIDCancelledItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellIDCancelledItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDCancelledItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDCancelledItemExtIEsExtContainerAPERValue) WithoutReplay() CellIDCancelledItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue is the concrete APERValue[CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer].
type CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue) WithoutReplay() CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTypeExtIEsExtContainerAPERValue is the concrete APERValue[CellTypeExtIEsExtContainer].
type CellTypeExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellTypeExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTypeExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTypeExtIEsExtContainerAPERValue) WithoutReplay() CellTypeExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinEAIItemExtIEsExtContainerAPERValue is the concrete APERValue[CompletedCellinEAIItemExtIEsExtContainer].
type CompletedCellinEAIItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CompletedCellinEAIItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinEAIItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinEAIItemExtIEsExtContainerAPERValue) WithoutReplay() CompletedCellinEAIItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinTAIItemExtIEsExtContainerAPERValue is the concrete APERValue[CompletedCellinTAIItemExtIEsExtContainer].
type CompletedCellinTAIItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CompletedCellinTAIItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinTAIItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinTAIItemExtIEsExtContainerAPERValue) WithoutReplay() CompletedCellinTAIItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectedengNBItemExtIEsExtContainerAPERValue is the concrete APERValue[ConnectedengNBItemExtIEsExtContainer].
type ConnectedengNBItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectedengNBItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectedengNBItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBItemExtIEsExtContainerAPERValue) WithoutReplay() ConnectedengNBItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ContextatSourceExtIEsExtContainerAPERValue is the concrete APERValue[ContextatSourceExtIEsExtContainer].
type ContextatSourceExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ContextatSourceExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ContextatSourceExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ContextatSourceExtIEsExtContainerAPERValue) WithoutReplay() ContextatSourceExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsExtIEsExtContainerAPERValue is the concrete APERValue[CriticalityDiagnosticsExtIEsExtContainer].
type CriticalityDiagnosticsExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CriticalityDiagnosticsExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsExtIEsExtContainerAPERValue) WithoutReplay() CriticalityDiagnosticsExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue is the concrete APERValue[CriticalityDiagnosticsIEItemExtIEsExtContainer].
type CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CriticalityDiagnosticsIEItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue) WithoutReplay() CriticalityDiagnosticsIEItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSRequestInfoExtIEsExtContainerAPERValue is the concrete APERValue[DAPSRequestInfoExtIEsExtContainer].
type DAPSRequestInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSRequestInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSRequestInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSRequestInfoExtIEsExtContainerAPERValue) WithoutReplay() DAPSRequestInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoExtIEsExtContainerAPERValue is the concrete APERValue[DAPSResponseInfoExtIEsExtContainer].
type DAPSResponseInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoExtIEsExtContainerAPERValue) WithoutReplay() DAPSResponseInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoItemExtIEsExtContainerAPERValue is the concrete APERValue[DAPSResponseInfoItemExtIEsExtContainer].
type DAPSResponseInfoItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoItemExtIEsExtContainerAPERValue) WithoutReplay() DAPSResponseInfoItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DLCPSecurityInformationExtIEsExtContainerAPERValue is the concrete APERValue[DLCPSecurityInformationExtIEsExtContainer].
type DLCPSecurityInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DLCPSecurityInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DLCPSecurityInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DLCPSecurityInformationExtIEsExtContainerAPERValue) WithoutReplay() DLCPSecurityInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue is the concrete APERValue[ENBStatusTransferTransparentContainerExtIEsExtContainer].
type ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferTransparentContainerExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue) WithoutReplay() ENBStatusTransferTransparentContainerExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBX2ExtTLAExtIEsExtContainerAPERValue is the concrete APERValue[ENBX2ExtTLAExtIEsExtContainer].
type ENBX2ExtTLAExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBX2ExtTLAExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBX2ExtTLAExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBX2ExtTLAExtIEsExtContainerAPERValue) WithoutReplay() ENBX2ExtTLAExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONConfigurationTransferExtIEsExtContainerAPERValue is the concrete APERValue[ENDCSONConfigurationTransferExtIEsExtContainer].
type ENDCSONConfigurationTransferExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCSONConfigurationTransferExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONConfigurationTransferExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONConfigurationTransferExtIEsExtContainerAPERValue) WithoutReplay() ENDCSONConfigurationTransferExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONeNBIdentificationExtIEsExtContainerAPERValue is the concrete APERValue[ENDCSONeNBIdentificationExtIEsExtContainer].
type ENDCSONeNBIdentificationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCSONeNBIdentificationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONeNBIdentificationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONeNBIdentificationExtIEsExtContainerAPERValue) WithoutReplay() ENDCSONeNBIdentificationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONengNBIdentificationExtIEsExtContainerAPERValue is the concrete APERValue[ENDCSONengNBIdentificationExtIEsExtContainer].
type ENDCSONengNBIdentificationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCSONengNBIdentificationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONengNBIdentificationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONengNBIdentificationExtIEsExtContainerAPERValue) WithoutReplay() ENDCSONengNBIdentificationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCTransferTypeReplyExtIEsExtContainerAPERValue is the concrete APERValue[ENDCTransferTypeReplyExtIEsExtContainer].
type ENDCTransferTypeReplyExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENDCTransferTypeReplyExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCTransferTypeReplyExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeReplyExtIEsExtContainerAPERValue) WithoutReplay() ENDCTransferTypeReplyExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DeactivateTraceIEFieldAPERValue is the concrete APERValue[DeactivateTraceIEField].
type DeactivateTraceIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DeactivateTraceIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DeactivateTraceIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DeactivateTraceIEFieldAPERValue) WithoutReplay() DeactivateTraceIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue is the concrete APERValue[DownlinkNonUEAssociatedLPPaTransportIEField].
type DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNonUEAssociatedLPPaTransportIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue) WithoutReplay() DownlinkNonUEAssociatedLPPaTransportIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkUEAssociatedLPPaTransportIEFieldAPERValue is the concrete APERValue[DownlinkUEAssociatedLPPaTransportIEField].
type DownlinkUEAssociatedLPPaTransportIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkUEAssociatedLPPaTransportIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkUEAssociatedLPPaTransportIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkUEAssociatedLPPaTransportIEFieldAPERValue) WithoutReplay() DownlinkUEAssociatedLPPaTransportIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DeactivateTraceIEContainerAPERValue is the concrete APERValue[DeactivateTraceIEContainer].
type DeactivateTraceIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DeactivateTraceIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DeactivateTraceIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DeactivateTraceIEContainerAPERValue) WithoutReplay() DeactivateTraceIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue is the concrete APERValue[DownlinkNonUEAssociatedLPPaTransportIEContainer].
type DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNonUEAssociatedLPPaTransportIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue) WithoutReplay() DownlinkNonUEAssociatedLPPaTransportIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkUEAssociatedLPPaTransportIEContainerAPERValue is the concrete APERValue[DownlinkUEAssociatedLPPaTransportIEContainer].
type DownlinkUEAssociatedLPPaTransportIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkUEAssociatedLPPaTransportIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkUEAssociatedLPPaTransportIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkUEAssociatedLPPaTransportIEContainerAPERValue) WithoutReplay() DownlinkUEAssociatedLPPaTransportIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[DeactivateTraceIEValueProtocolErrorIEContainerList].
type DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DeactivateTraceIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() DeactivateTraceIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList].
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList].
type DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DeactivateTraceIEValueProtocolIEContainerListAPERValue is the concrete APERValue[DeactivateTraceIEValueProtocolIEContainerList].
type DeactivateTraceIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DeactivateTraceIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DeactivateTraceIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DeactivateTraceIEValueProtocolIEContainerListAPERValue) WithoutReplay() DeactivateTraceIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue is the concrete APERValue[DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList].
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue) WithoutReplay() DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue is the concrete APERValue[DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList].
type DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue) WithoutReplay() DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APDeactivateTraceIEValue(v *DeactivateTraceIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(86):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANTraceID == nil)
				if v.rowEUTRANTraceID != nil {
					s00.BridgeCaptureS1APEUTRANTraceID(v.rowEUTRANTraceID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DeactivateTraceIEValue) captureSemantics(s aper.SemanticCapture) DeactivateTraceIEValue {
	BridgeCaptureS1APDeactivateTraceIEValue(&v, &s)
	return v
}
func BridgeCompareS1APDeactivateTraceIEValue(v *DeactivateTraceIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(86):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANTraceID == nil)
				if v.rowEUTRANTraceID != nil {
					s02.BridgeCompareS1APEUTRANTraceID(v.rowEUTRANTraceID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DeactivateTraceIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APDeactivateTraceIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APDownlinkNonUEAssociatedLPPaTransportIEValue(v *DownlinkNonUEAssociatedLPPaTransportIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(148):
			{
				f := s.Begin()
				s.Bool(v.rowRoutingID == nil)
				if v.rowRoutingID != nil {
					s00.BridgeCaptureS1APRoutingID(v.rowRoutingID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(147):
			{
				f := s.Begin()
				s.Bool(v.rowLPPaPDU == nil)
				if v.rowLPPaPDU != nil {
					s00.BridgeCaptureS1APLPPaPDU(v.rowLPPaPDU, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkNonUEAssociatedLPPaTransportIEValue) captureSemantics(s aper.SemanticCapture) DownlinkNonUEAssociatedLPPaTransportIEValue {
	BridgeCaptureS1APDownlinkNonUEAssociatedLPPaTransportIEValue(&v, &s)
	return v
}
func BridgeCompareS1APDownlinkNonUEAssociatedLPPaTransportIEValue(v *DownlinkNonUEAssociatedLPPaTransportIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(148):
			{
				f := s.Begin()
				s.Bool(v.rowRoutingID == nil)
				if v.rowRoutingID != nil {
					s08.BridgeCompareS1APRoutingID(v.rowRoutingID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(147):
			{
				f := s.Begin()
				s.Bool(v.rowLPPaPDU == nil)
				if v.rowLPPaPDU != nil {
					s02.BridgeCompareS1APLPPaPDU(v.rowLPPaPDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkNonUEAssociatedLPPaTransportIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APDownlinkNonUEAssociatedLPPaTransportIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APDownlinkUEAssociatedLPPaTransportIEValue(v *DownlinkUEAssociatedLPPaTransportIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(148):
			{
				f := s.Begin()
				s.Bool(v.rowRoutingID == nil)
				if v.rowRoutingID != nil {
					s00.BridgeCaptureS1APRoutingID(v.rowRoutingID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(147):
			{
				f := s.Begin()
				s.Bool(v.rowLPPaPDU == nil)
				if v.rowLPPaPDU != nil {
					s00.BridgeCaptureS1APLPPaPDU(v.rowLPPaPDU, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkUEAssociatedLPPaTransportIEValue) captureSemantics(s aper.SemanticCapture) DownlinkUEAssociatedLPPaTransportIEValue {
	BridgeCaptureS1APDownlinkUEAssociatedLPPaTransportIEValue(&v, &s)
	return v
}
func BridgeCompareS1APDownlinkUEAssociatedLPPaTransportIEValue(v *DownlinkUEAssociatedLPPaTransportIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(148):
			{
				f := s.Begin()
				s.Bool(v.rowRoutingID == nil)
				if v.rowRoutingID != nil {
					s08.BridgeCompareS1APRoutingID(v.rowRoutingID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(147):
			{
				f := s.Begin()
				s.Bool(v.rowLPPaPDU == nil)
				if v.rowLPPaPDU != nil {
					s02.BridgeCompareS1APLPPaPDU(v.rowLPPaPDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkUEAssociatedLPPaTransportIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APDownlinkUEAssociatedLPPaTransportIEValue(&v, &s)
	return s
}

type DeactivateTraceIEValue struct {
	id               s00.ProtocolIEID
	received         aper.WireSpan
	replay           aper.Snapshot
	opaque           aper.OpaqueOpenType
	isOpaque         bool
	rowMMEUES1APID   *s00.MMEUES1APID
	rowENBUES1APID   *s00.ENBUES1APID
	rowEUTRANTraceID *s00.EUTRANTraceID
}

func (v DeactivateTraceIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(86):
		return v.rowEUTRANTraceID != nil
	}
	return false
}

// Opaque returns the retained opaque open value of DeactivateTraceIEValue and reports whether the opaque alternative is selected.
func (v *DeactivateTraceIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (DeactivateTraceIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DeactivateTraceIEs"}}
}
func (DeactivateTraceIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(86):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of DeactivateTraceIEValue and reports whether that alternative is active.
func (v *DeactivateTraceIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of DeactivateTraceIEValue and reports whether that alternative is active.
func (v *DeactivateTraceIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsEUTRANTraceID returns the selected EUTRANTraceID value of DeactivateTraceIEValue and reports whether that alternative is active.
func (v *DeactivateTraceIEValue) AsEUTRANTraceID() (*s00.EUTRANTraceID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(86) || v.rowEUTRANTraceID == nil {
		return nil, false
	}
	return v.rowEUTRANTraceID, true
}
func (v DeactivateTraceIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (DeactivateTraceIEValue, error) {
	out := DeactivateTraceIEValue{id: id}
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
	case s00.ProtocolIEID(86):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.EUTRANTraceID, error) {
			var v struct{ Value s00.EUTRANTraceID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 8, 8, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.EUTRANTraceID(val_value)
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
		out.rowEUTRANTraceID = &value
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
func (v DeactivateTraceIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v DeactivateTraceIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "DeactivateTraceIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "DeactivateTraceIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(86):
		if v.rowEUTRANTraceID == nil {
			return nil, fmt.Errorf("%s missing value", "DeactivateTraceIEs.id-E-UTRAN-Trace-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.EUTRANTraceID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.EUTRANTraceID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 8, 8, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowEUTRANTraceID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "DeactivateTraceIEValue:", v.id)
	}
}

type DownlinkNonUEAssociatedLPPaTransportIEValue struct {
	id           s00.ProtocolIEID
	received     aper.WireSpan
	replay       aper.Snapshot
	opaque       aper.OpaqueOpenType
	isOpaque     bool
	rowRoutingID *s00.RoutingID
	rowLPPaPDU   *s00.LPPaPDU
}

func (v DownlinkNonUEAssociatedLPPaTransportIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(148):
		return v.rowRoutingID != nil
	case s00.ProtocolIEID(147):
		return v.rowLPPaPDU != nil
	}
	return false
}

// Opaque returns the retained opaque open value of DownlinkNonUEAssociatedLPPaTransportIEValue and reports whether the opaque alternative is selected.
func (v *DownlinkNonUEAssociatedLPPaTransportIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (DownlinkNonUEAssociatedLPPaTransportIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNonUEAssociatedLPPaTransport-IEs"}}
}
func (DownlinkNonUEAssociatedLPPaTransportIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(148):
		return aper.UnknownSelector
	case s00.ProtocolIEID(147):
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

// AsRoutingID returns the selected RoutingID value of DownlinkNonUEAssociatedLPPaTransportIEValue and reports whether that alternative is active.
func (v *DownlinkNonUEAssociatedLPPaTransportIEValue) AsRoutingID() (*s00.RoutingID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(148) || v.rowRoutingID == nil {
		return nil, false
	}
	return v.rowRoutingID, true
}

// AsLPPaPDU returns the selected LPPaPDU value of DownlinkNonUEAssociatedLPPaTransportIEValue and reports whether that alternative is active.
func (v *DownlinkNonUEAssociatedLPPaTransportIEValue) AsLPPaPDU() (*s00.LPPaPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(147) || v.rowLPPaPDU == nil {
		return nil, false
	}
	return v.rowLPPaPDU, true
}
func (v DownlinkNonUEAssociatedLPPaTransportIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (DownlinkNonUEAssociatedLPPaTransportIEValue, error) {
	out := DownlinkNonUEAssociatedLPPaTransportIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(148):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
		value := s00.RoutingID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RoutingID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRoutingID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(147):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.LPPaPDU, error) {
			var v struct{ Value s00.LPPaPDU }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.LPPaPDU(val_value)
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
		out.rowLPPaPDU = &value
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
func (v DownlinkNonUEAssociatedLPPaTransportIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v DownlinkNonUEAssociatedLPPaTransportIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(148):
		if v.rowRoutingID == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNonUEAssociatedLPPaTransport-IEs.id-Routing-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowRoutingID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(147):
		if v.rowLPPaPDU == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNonUEAssociatedLPPaTransport-IEs.id-LPPa-PDU:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.LPPaPDU, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.LPPaPDU }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowLPPaPDU, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "DownlinkNonUEAssociatedLPPaTransportIEValue:", v.id)
	}
}

type DownlinkUEAssociatedLPPaTransportIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
	rowRoutingID   *s00.RoutingID
	rowLPPaPDU     *s00.LPPaPDU
}

func (v DownlinkUEAssociatedLPPaTransportIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(148):
		return v.rowRoutingID != nil
	case s00.ProtocolIEID(147):
		return v.rowLPPaPDU != nil
	}
	return false
}

// Opaque returns the retained opaque open value of DownlinkUEAssociatedLPPaTransportIEValue and reports whether the opaque alternative is selected.
func (v *DownlinkUEAssociatedLPPaTransportIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (DownlinkUEAssociatedLPPaTransportIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkUEAssociatedLPPaTransport-IEs"}}
}
func (DownlinkUEAssociatedLPPaTransportIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(148):
		return aper.UnknownSelector
	case s00.ProtocolIEID(147):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of DownlinkUEAssociatedLPPaTransportIEValue and reports whether that alternative is active.
func (v *DownlinkUEAssociatedLPPaTransportIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of DownlinkUEAssociatedLPPaTransportIEValue and reports whether that alternative is active.
func (v *DownlinkUEAssociatedLPPaTransportIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsRoutingID returns the selected RoutingID value of DownlinkUEAssociatedLPPaTransportIEValue and reports whether that alternative is active.
func (v *DownlinkUEAssociatedLPPaTransportIEValue) AsRoutingID() (*s00.RoutingID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(148) || v.rowRoutingID == nil {
		return nil, false
	}
	return v.rowRoutingID, true
}

// AsLPPaPDU returns the selected LPPaPDU value of DownlinkUEAssociatedLPPaTransportIEValue and reports whether that alternative is active.
func (v *DownlinkUEAssociatedLPPaTransportIEValue) AsLPPaPDU() (*s00.LPPaPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(147) || v.rowLPPaPDU == nil {
		return nil, false
	}
	return v.rowLPPaPDU, true
}
func (v DownlinkUEAssociatedLPPaTransportIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (DownlinkUEAssociatedLPPaTransportIEValue, error) {
	out := DownlinkUEAssociatedLPPaTransportIEValue{id: id}
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
	case s00.ProtocolIEID(148):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
		value := s00.RoutingID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RoutingID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRoutingID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(147):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.LPPaPDU, error) {
			var v struct{ Value s00.LPPaPDU }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.LPPaPDU(val_value)
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
		out.rowLPPaPDU = &value
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
func (v DownlinkUEAssociatedLPPaTransportIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v DownlinkUEAssociatedLPPaTransportIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "DownlinkUEAssociatedLPPaTransport-IEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "DownlinkUEAssociatedLPPaTransport-IEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(148):
		if v.rowRoutingID == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkUEAssociatedLPPaTransport-IEs.id-Routing-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowRoutingID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(147):
		if v.rowLPPaPDU == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkUEAssociatedLPPaTransport-IEs.id-LPPa-PDU:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.LPPaPDU, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.LPPaPDU }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowLPPaPDU, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "DownlinkUEAssociatedLPPaTransportIEValue:", v.id)
	}
}

type CellIDBroadcastItemExtIETable struct{}

func CellIDBroadcastItemExtIEs() CellIDBroadcastItemExtIETable {
	return CellIDBroadcastItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CellIDBroadcastItemExtIETable.
func (CellIDBroadcastItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellID-Broadcast-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CellIDBroadcastItemExtIETable.
func (CellIDBroadcastItemExtIETable) Table() s00.CellIDBroadcastItemExtIEsValueExtensionTable {
	return func() s00.CellIDBroadcastItemExtIEsValueExtensionTable {
		sealed := s00.CellIDBroadcastItemExtIEsValueExtensionTable{}
		*s00.BridgeCellIDBroadcastItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CellIDBroadcastItemExtIETable.
func (t CellIDBroadcastItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CellIDBroadcastItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CellIDBroadcastItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CellIDBroadcastItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CellIDBroadcastItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CellIDBroadcastItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CellIDBroadcastItemExtIEsValue {
			sealed := s03.CellIDBroadcastItemExtIEsValue{}
			*s03.BridgeCellIDBroadcastItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCellIDBroadcastItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCellIDBroadcastItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CellIDCancelledItemExtIETable struct{}

func CellIDCancelledItemExtIEs() CellIDCancelledItemExtIETable {
	return CellIDCancelledItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CellIDCancelledItemExtIETable.
func (CellIDCancelledItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellID-Cancelled-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CellIDCancelledItemExtIETable.
func (CellIDCancelledItemExtIETable) Table() s00.CellIDCancelledItemExtIEsValueExtensionTable {
	return func() s00.CellIDCancelledItemExtIEsValueExtensionTable {
		sealed := s00.CellIDCancelledItemExtIEsValueExtensionTable{}
		*s00.BridgeCellIDCancelledItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CellIDCancelledItemExtIETable.
func (t CellIDCancelledItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CellIDCancelledItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CellIDCancelledItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CellIDCancelledItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CellIDCancelledItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CellIDCancelledItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CellIDCancelledItemExtIEsValue {
			sealed := s03.CellIDCancelledItemExtIEsValue{}
			*s03.BridgeCellIDCancelledItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCellIDCancelledItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCellIDCancelledItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CellIdentifierAndCELevelForCECapableUEsExtIETable struct{}

func CellIdentifierAndCELevelForCECapableUEsExtIEs() CellIdentifierAndCELevelForCECapableUEsExtIETable {
	return CellIdentifierAndCELevelForCECapableUEsExtIETable{}
}

// ID returns the ASN.1 object-set identity of CellIdentifierAndCELevelForCECapableUEsExtIETable.
func (CellIdentifierAndCELevelForCECapableUEsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellIdentifierAndCELevelForCECapableUEs-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CellIdentifierAndCELevelForCECapableUEsExtIETable.
func (CellIdentifierAndCELevelForCECapableUEsExtIETable) Table() s00.CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTable {
	return func() s00.CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTable {
		sealed := s00.CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTable{}
		*s00.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CellIdentifierAndCELevelForCECapableUEsExtIETable.
func (t CellIdentifierAndCELevelForCECapableUEsExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CellIdentifierAndCELevelForCECapableUEsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CellIdentifierAndCELevelForCECapableUEsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CellIdentifierAndCELevelForCECapableUEsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue {
			sealed := s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue{}
			*s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CellTypeExtIETable struct{}

func CellTypeExtIEs() CellTypeExtIETable { return CellTypeExtIETable{} }

// ID returns the ASN.1 object-set identity of CellTypeExtIETable.
func (CellTypeExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellType-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CellTypeExtIETable.
func (CellTypeExtIETable) Table() s00.CellTypeExtIEsValueExtensionTable {
	return func() s00.CellTypeExtIEsValueExtensionTable {
		sealed := s00.CellTypeExtIEsValueExtensionTable{}
		*s00.BridgeCellTypeExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CellTypeExtIETable.
func (t CellTypeExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CellTypeExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CellTypeExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CellTypeExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CellTypeExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CellTypeExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CellTypeExtIEsValue {
			sealed := s03.CellTypeExtIEsValue{}
			*s03.BridgeCellTypeExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCellTypeExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCellTypeExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CompletedCellinEAIItemExtIETable struct{}

func CompletedCellinEAIItemExtIEs() CompletedCellinEAIItemExtIETable {
	return CompletedCellinEAIItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CompletedCellinEAIItemExtIETable.
func (CompletedCellinEAIItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CompletedCellinEAI-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CompletedCellinEAIItemExtIETable.
func (CompletedCellinEAIItemExtIETable) Table() s00.CompletedCellinEAIItemExtIEsValueExtensionTable {
	return func() s00.CompletedCellinEAIItemExtIEsValueExtensionTable {
		sealed := s00.CompletedCellinEAIItemExtIEsValueExtensionTable{}
		*s00.BridgeCompletedCellinEAIItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CompletedCellinEAIItemExtIETable.
func (t CompletedCellinEAIItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CompletedCellinEAIItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CompletedCellinEAIItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CompletedCellinEAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CompletedCellinEAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CompletedCellinEAIItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CompletedCellinEAIItemExtIEsValue {
			sealed := s03.CompletedCellinEAIItemExtIEsValue{}
			*s03.BridgeCompletedCellinEAIItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCompletedCellinEAIItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCompletedCellinEAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CompletedCellinTAIItemExtIETable struct{}

func CompletedCellinTAIItemExtIEs() CompletedCellinTAIItemExtIETable {
	return CompletedCellinTAIItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CompletedCellinTAIItemExtIETable.
func (CompletedCellinTAIItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CompletedCellinTAI-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CompletedCellinTAIItemExtIETable.
func (CompletedCellinTAIItemExtIETable) Table() s00.CompletedCellinTAIItemExtIEsValueExtensionTable {
	return func() s00.CompletedCellinTAIItemExtIEsValueExtensionTable {
		sealed := s00.CompletedCellinTAIItemExtIEsValueExtensionTable{}
		*s00.BridgeCompletedCellinTAIItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CompletedCellinTAIItemExtIETable.
func (t CompletedCellinTAIItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CompletedCellinTAIItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CompletedCellinTAIItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CompletedCellinTAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CompletedCellinTAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CompletedCellinTAIItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CompletedCellinTAIItemExtIEsValue {
			sealed := s03.CompletedCellinTAIItemExtIEsValue{}
			*s03.BridgeCompletedCellinTAIItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCompletedCellinTAIItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCompletedCellinTAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ConnectedengNBItemExtIETable struct{}

func ConnectedengNBItemExtIEs() ConnectedengNBItemExtIETable { return ConnectedengNBItemExtIETable{} }

// ID returns the ASN.1 object-set identity of ConnectedengNBItemExtIETable.
func (ConnectedengNBItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ConnectedengNBItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ConnectedengNBItemExtIETable.
func (ConnectedengNBItemExtIETable) Table() s00.ConnectedengNBItemExtIEsValueExtensionTable {
	return func() s00.ConnectedengNBItemExtIEsValueExtensionTable {
		sealed := s00.ConnectedengNBItemExtIEsValueExtensionTable{}
		*s00.BridgeConnectedengNBItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ConnectedengNBItemExtIETable.
func (t ConnectedengNBItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ConnectedengNBItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ConnectedengNBItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ConnectedengNBItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ConnectedengNBItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ConnectedengNBItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.ConnectedengNBItemExtIEsValue {
			sealed := s03.ConnectedengNBItemExtIEsValue{}
			*s03.BridgeConnectedengNBItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeConnectedengNBItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeConnectedengNBItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ContextatSourceExtIETable struct{}

func ContextatSourceExtIEs() ContextatSourceExtIETable { return ContextatSourceExtIETable{} }

// ID returns the ASN.1 object-set identity of ContextatSourceExtIETable.
func (ContextatSourceExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ContextatSource-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ContextatSourceExtIETable.
func (ContextatSourceExtIETable) Table() s00.ContextatSourceExtIEsValueExtensionTable {
	return func() s00.ContextatSourceExtIEsValueExtensionTable {
		sealed := s00.ContextatSourceExtIEsValueExtensionTable{}
		*s00.BridgeContextatSourceExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ContextatSourceExtIETable.
func (t ContextatSourceExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ContextatSourceExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ContextatSourceExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ContextatSourceExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ContextatSourceExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ContextatSourceExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.ContextatSourceExtIEsValue {
			sealed := s03.ContextatSourceExtIEsValue{}
			*s03.BridgeContextatSourceExtIEsValueFieldId(&sealed) = id
			*s03.BridgeContextatSourceExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeContextatSourceExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CriticalityDiagnosticsExtIETable struct{}

func CriticalityDiagnosticsExtIEs() CriticalityDiagnosticsExtIETable {
	return CriticalityDiagnosticsExtIETable{}
}

// ID returns the ASN.1 object-set identity of CriticalityDiagnosticsExtIETable.
func (CriticalityDiagnosticsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CriticalityDiagnosticsExtIETable.
func (CriticalityDiagnosticsExtIETable) Table() s00.CriticalityDiagnosticsExtIEsValueExtensionTable {
	return func() s00.CriticalityDiagnosticsExtIEsValueExtensionTable {
		sealed := s00.CriticalityDiagnosticsExtIEsValueExtensionTable{}
		*s00.BridgeCriticalityDiagnosticsExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CriticalityDiagnosticsExtIETable.
func (t CriticalityDiagnosticsExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CriticalityDiagnosticsExtIEsExtField, error) {
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
		return CriticalityDiagnosticsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CriticalityDiagnosticsExtIEsValue {
			sealed := s03.CriticalityDiagnosticsExtIEsValue{}
			*s03.BridgeCriticalityDiagnosticsExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCriticalityDiagnosticsExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCriticalityDiagnosticsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CriticalityDiagnosticsIEItemExtIETable struct{}

func CriticalityDiagnosticsIEItemExtIEs() CriticalityDiagnosticsIEItemExtIETable {
	return CriticalityDiagnosticsIEItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CriticalityDiagnosticsIEItemExtIETable.
func (CriticalityDiagnosticsIEItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics-IE-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CriticalityDiagnosticsIEItemExtIETable.
func (CriticalityDiagnosticsIEItemExtIETable) Table() s00.CriticalityDiagnosticsIEItemExtIEsValueExtensionTable {
	return func() s00.CriticalityDiagnosticsIEItemExtIEsValueExtensionTable {
		sealed := s00.CriticalityDiagnosticsIEItemExtIEsValueExtensionTable{}
		*s00.BridgeCriticalityDiagnosticsIEItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CriticalityDiagnosticsIEItemExtIETable.
func (t CriticalityDiagnosticsIEItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CriticalityDiagnosticsIEItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CriticalityDiagnosticsIEItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CriticalityDiagnosticsIEItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CriticalityDiagnosticsIEItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CriticalityDiagnosticsIEItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CriticalityDiagnosticsIEItemExtIEsValue {
			sealed := s03.CriticalityDiagnosticsIEItemExtIEsValue{}
			*s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type DAPSRequestInfoExtIETable struct{}

func DAPSRequestInfoExtIEs() DAPSRequestInfoExtIETable { return DAPSRequestInfoExtIETable{} }

// ID returns the ASN.1 object-set identity of DAPSRequestInfoExtIETable.
func (DAPSRequestInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSRequestInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DAPSRequestInfoExtIETable.
func (DAPSRequestInfoExtIETable) Table() s00.DAPSRequestInfoExtIEsValueExtensionTable {
	return func() s00.DAPSRequestInfoExtIEsValueExtensionTable {
		sealed := s00.DAPSRequestInfoExtIEsValueExtensionTable{}
		*s00.BridgeDAPSRequestInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DAPSRequestInfoExtIETable.
func (t DAPSRequestInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (DAPSRequestInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DAPSRequestInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DAPSRequestInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DAPSRequestInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return DAPSRequestInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.DAPSRequestInfoExtIEsValue {
			sealed := s03.DAPSRequestInfoExtIEsValue{}
			*s03.BridgeDAPSRequestInfoExtIEsValueFieldId(&sealed) = id
			*s03.BridgeDAPSRequestInfoExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeDAPSRequestInfoExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type DAPSResponseInfoExtIETable struct{}

func DAPSResponseInfoExtIEs() DAPSResponseInfoExtIETable { return DAPSResponseInfoExtIETable{} }

// ID returns the ASN.1 object-set identity of DAPSResponseInfoExtIETable.
func (DAPSResponseInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DAPSResponseInfoExtIETable.
func (DAPSResponseInfoExtIETable) Table() s00.DAPSResponseInfoExtIEsValueExtensionTable {
	return func() s00.DAPSResponseInfoExtIEsValueExtensionTable {
		sealed := s00.DAPSResponseInfoExtIEsValueExtensionTable{}
		*s00.BridgeDAPSResponseInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DAPSResponseInfoExtIETable.
func (t DAPSResponseInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (DAPSResponseInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DAPSResponseInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DAPSResponseInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DAPSResponseInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return DAPSResponseInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.DAPSResponseInfoExtIEsValue {
			sealed := s03.DAPSResponseInfoExtIEsValue{}
			*s03.BridgeDAPSResponseInfoExtIEsValueFieldId(&sealed) = id
			*s03.BridgeDAPSResponseInfoExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeDAPSResponseInfoExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type DAPSResponseInfoItemExtIETable struct{}

func DAPSResponseInfoItemExtIEs() DAPSResponseInfoItemExtIETable {
	return DAPSResponseInfoItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of DAPSResponseInfoItemExtIETable.
func (DAPSResponseInfoItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DAPSResponseInfoItemExtIETable.
func (DAPSResponseInfoItemExtIETable) Table() s00.DAPSResponseInfoItemExtIEsValueExtensionTable {
	return func() s00.DAPSResponseInfoItemExtIEsValueExtensionTable {
		sealed := s00.DAPSResponseInfoItemExtIEsValueExtensionTable{}
		*s00.BridgeDAPSResponseInfoItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DAPSResponseInfoItemExtIETable.
func (t DAPSResponseInfoItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (DAPSResponseInfoItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DAPSResponseInfoItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DAPSResponseInfoItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DAPSResponseInfoItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return DAPSResponseInfoItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.DAPSResponseInfoItemExtIEsValue {
			sealed := s04.DAPSResponseInfoItemExtIEsValue{}
			*s04.BridgeDAPSResponseInfoItemExtIEsValueFieldId(&sealed) = id
			*s04.BridgeDAPSResponseInfoItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeDAPSResponseInfoItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type DLCPSecurityInformationExtIETable struct{}

func DLCPSecurityInformationExtIEs() DLCPSecurityInformationExtIETable {
	return DLCPSecurityInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of DLCPSecurityInformationExtIETable.
func (DLCPSecurityInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DL-CP-SecurityInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DLCPSecurityInformationExtIETable.
func (DLCPSecurityInformationExtIETable) Table() s00.DLCPSecurityInformationExtIEsValueExtensionTable {
	return func() s00.DLCPSecurityInformationExtIEsValueExtensionTable {
		sealed := s00.DLCPSecurityInformationExtIEsValueExtensionTable{}
		*s00.BridgeDLCPSecurityInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DLCPSecurityInformationExtIETable.
func (t DLCPSecurityInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (DLCPSecurityInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DLCPSecurityInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DLCPSecurityInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DLCPSecurityInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return DLCPSecurityInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.DLCPSecurityInformationExtIEsValue {
			sealed := s04.DLCPSecurityInformationExtIEsValue{}
			*s04.BridgeDLCPSecurityInformationExtIEsValueFieldId(&sealed) = id
			*s04.BridgeDLCPSecurityInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeDLCPSecurityInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ENDCSONConfigurationTransferExtIETable struct{}

func ENDCSONConfigurationTransferExtIEs() ENDCSONConfigurationTransferExtIETable {
	return ENDCSONConfigurationTransferExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENDCSONConfigurationTransferExtIETable.
func (ENDCSONConfigurationTransferExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EN-DCSONConfigurationTransfer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENDCSONConfigurationTransferExtIETable.
func (ENDCSONConfigurationTransferExtIETable) Table() s00.ENDCSONConfigurationTransferExtIEsValueExtensionTable {
	return func() s00.ENDCSONConfigurationTransferExtIEsValueExtensionTable {
		sealed := s00.ENDCSONConfigurationTransferExtIEsValueExtensionTable{}
		*s00.BridgeENDCSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENDCSONConfigurationTransferExtIETable.
func (t ENDCSONConfigurationTransferExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENDCSONConfigurationTransferExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENDCSONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENDCSONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENDCSONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENDCSONConfigurationTransferExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ENDCSONConfigurationTransferExtIEsValue {
			sealed := s04.ENDCSONConfigurationTransferExtIEsValue{}
			*s04.BridgeENDCSONConfigurationTransferExtIEsValueFieldId(&sealed) = id
			*s04.BridgeENDCSONConfigurationTransferExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeENDCSONConfigurationTransferExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ENDCSONeNBIdentificationExtIETable struct{}

func ENDCSONeNBIdentificationExtIEs() ENDCSONeNBIdentificationExtIETable {
	return ENDCSONeNBIdentificationExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENDCSONeNBIdentificationExtIETable.
func (ENDCSONeNBIdentificationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EN-DCSONeNBIdentification-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENDCSONeNBIdentificationExtIETable.
func (ENDCSONeNBIdentificationExtIETable) Table() s00.ENDCSONeNBIdentificationExtIEsValueExtensionTable {
	return func() s00.ENDCSONeNBIdentificationExtIEsValueExtensionTable {
		sealed := s00.ENDCSONeNBIdentificationExtIEsValueExtensionTable{}
		*s00.BridgeENDCSONeNBIdentificationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENDCSONeNBIdentificationExtIETable.
func (t ENDCSONeNBIdentificationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENDCSONeNBIdentificationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENDCSONeNBIdentificationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENDCSONeNBIdentificationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENDCSONeNBIdentificationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENDCSONeNBIdentificationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ENDCSONeNBIdentificationExtIEsValue {
			sealed := s04.ENDCSONeNBIdentificationExtIEsValue{}
			*s04.BridgeENDCSONeNBIdentificationExtIEsValueFieldId(&sealed) = id
			*s04.BridgeENDCSONeNBIdentificationExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeENDCSONeNBIdentificationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ENDCSONengNBIdentificationExtIETable struct{}

func ENDCSONengNBIdentificationExtIEs() ENDCSONengNBIdentificationExtIETable {
	return ENDCSONengNBIdentificationExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENDCSONengNBIdentificationExtIETable.
func (ENDCSONengNBIdentificationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EN-DCSONengNBIdentification-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENDCSONengNBIdentificationExtIETable.
func (ENDCSONengNBIdentificationExtIETable) Table() s00.ENDCSONengNBIdentificationExtIEsValueExtensionTable {
	return func() s00.ENDCSONengNBIdentificationExtIEsValueExtensionTable {
		sealed := s00.ENDCSONengNBIdentificationExtIEsValueExtensionTable{}
		*s00.BridgeENDCSONengNBIdentificationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENDCSONengNBIdentificationExtIETable.
func (t ENDCSONengNBIdentificationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENDCSONengNBIdentificationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENDCSONengNBIdentificationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENDCSONengNBIdentificationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENDCSONengNBIdentificationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENDCSONengNBIdentificationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ENDCSONengNBIdentificationExtIEsValue {
			sealed := s04.ENDCSONengNBIdentificationExtIEsValue{}
			*s04.BridgeENDCSONengNBIdentificationExtIEsValueFieldId(&sealed) = id
			*s04.BridgeENDCSONengNBIdentificationExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeENDCSONengNBIdentificationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ENDCTransferTypeReplyExtIETable struct{}

func ENDCTransferTypeReplyExtIEs() ENDCTransferTypeReplyExtIETable {
	return ENDCTransferTypeReplyExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENDCTransferTypeReplyExtIETable.
func (ENDCTransferTypeReplyExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EN-DCTransferTypeReply-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENDCTransferTypeReplyExtIETable.
func (ENDCTransferTypeReplyExtIETable) Table() s00.ENDCTransferTypeReplyExtIEsValueExtensionTable {
	return func() s00.ENDCTransferTypeReplyExtIEsValueExtensionTable {
		sealed := s00.ENDCTransferTypeReplyExtIEsValueExtensionTable{}
		*s00.BridgeENDCTransferTypeReplyExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENDCTransferTypeReplyExtIETable.
func (t ENDCTransferTypeReplyExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENDCTransferTypeReplyExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENDCTransferTypeReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENDCTransferTypeReplyExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENDCTransferTypeReplyExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENDCTransferTypeReplyExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ENDCTransferTypeReplyExtIEsValue {
			sealed := s04.ENDCTransferTypeReplyExtIEsValue{}
			*s04.BridgeENDCTransferTypeReplyExtIEsValueFieldId(&sealed) = id
			*s04.BridgeENDCTransferTypeReplyExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeENDCTransferTypeReplyExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ENBStatusTransferTransparentContainerExtIETable struct{}

func ENBStatusTransferTransparentContainerExtIEs() ENBStatusTransferTransparentContainerExtIETable {
	return ENBStatusTransferTransparentContainerExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENBStatusTransferTransparentContainerExtIETable.
func (ENBStatusTransferTransparentContainerExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-StatusTransfer-TransparentContainer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBStatusTransferTransparentContainerExtIETable.
func (ENBStatusTransferTransparentContainerExtIETable) Table() s00.ENBStatusTransferTransparentContainerExtIEsValueExtensionTable {
	return func() s00.ENBStatusTransferTransparentContainerExtIEsValueExtensionTable {
		sealed := s00.ENBStatusTransferTransparentContainerExtIEsValueExtensionTable{}
		*s00.BridgeENBStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBStatusTransferTransparentContainerExtIETable.
func (t ENBStatusTransferTransparentContainerExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENBStatusTransferTransparentContainerExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENBStatusTransferTransparentContainerExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ENBStatusTransferTransparentContainerExtIEsValue {
			sealed := s04.ENBStatusTransferTransparentContainerExtIEsValue{}
			*s04.BridgeENBStatusTransferTransparentContainerExtIEsValueFieldId(&sealed) = id
			*s04.BridgeENBStatusTransferTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeENBStatusTransferTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ENBX2ExtTLAExtIETable struct{}

func ENBX2ExtTLAExtIEs() ENBX2ExtTLAExtIETable { return ENBX2ExtTLAExtIETable{} }

// ID returns the ASN.1 object-set identity of ENBX2ExtTLAExtIETable.
func (ENBX2ExtTLAExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENBX2ExtTLA-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBX2ExtTLAExtIETable.
func (ENBX2ExtTLAExtIETable) Table() s00.ENBX2ExtTLAExtIEsValueExtensionTable {
	return func() s00.ENBX2ExtTLAExtIEsValueExtensionTable {
		sealed := s00.ENBX2ExtTLAExtIEsValueExtensionTable{}
		*s00.BridgeENBX2ExtTLAExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBX2ExtTLAExtIETable.
func (t ENBX2ExtTLAExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENBX2ExtTLAExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBX2ExtTLAExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBX2ExtTLAExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBX2ExtTLAExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENBX2ExtTLAExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s04.ENBX2ExtTLAExtIEsValue {
			sealed := s04.ENBX2ExtTLAExtIEsValue{}
			*s04.BridgeENBX2ExtTLAExtIEsValueFieldId(&sealed) = id
			*s04.BridgeENBX2ExtTLAExtIEsValueFieldOpaque(&sealed) = opaque
			*s04.BridgeENBX2ExtTLAExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type DeactivateTraceIETable struct{}

func DeactivateTraceIEs() DeactivateTraceIETable { return DeactivateTraceIETable{} }

// ID returns the ASN.1 object-set identity of DeactivateTraceIETable.
func (DeactivateTraceIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DeactivateTraceIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DeactivateTraceIETable.
func (DeactivateTraceIETable) Table() s00.DeactivateTraceIEValueIETable {
	return func() s00.DeactivateTraceIEValueIETable {
		sealed := s00.DeactivateTraceIEValueIETable{}
		*s00.BridgeDeactivateTraceIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (DeactivateTraceIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DeactivateTraceIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DeactivateTraceIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of DeactivateTraceIETable.
func (t DeactivateTraceIETable) MMEUES1APID() DeactivateTraceMMEUES1APIDIEBinding {
	return DeactivateTraceMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero DeactivateTraceIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding DeactivateTraceIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DeactivateTraceIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) DeactivateTraceIEValue {
			return DeactivateTraceIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *DeactivateTraceIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (DeactivateTraceIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DeactivateTraceIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DeactivateTraceIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of DeactivateTraceIETable.
func (t DeactivateTraceIETable) ENBUES1APID() DeactivateTraceENBUES1APIDIEBinding {
	return DeactivateTraceENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero DeactivateTraceIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding DeactivateTraceIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DeactivateTraceIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) DeactivateTraceIEValue {
			return DeactivateTraceIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *DeactivateTraceIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (DeactivateTraceIETable) infoEUTRANTraceID() s00.FieldInfo {
	return s00.FieldInfo{Table: DeactivateTraceIEs().ID(), ID: s00.ProtocolIEID(86), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-UTRAN-Trace-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DeactivateTraceIEs", Row: "id-E-UTRAN-Trace-ID"}}}
}

// EUTRANTraceID returns the typed binding for the EUTRANTraceID row of DeactivateTraceIETable.
func (t DeactivateTraceIETable) EUTRANTraceID() DeactivateTraceEUTRANTraceIDIEBinding {
	return DeactivateTraceEUTRANTraceIDIEBinding{info: t.infoEUTRANTraceID(), codec: func() s00.EUTRANTraceIDValueCodec {
		sealed := s00.EUTRANTraceIDValueCodec{}
		*s00.BridgeEUTRANTraceIDValueCodecFieldPath(&sealed) = "EUTRANTraceID"
		*s00.BridgeEUTRANTraceIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EUTRANTraceID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EUTRANTraceID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANTraceID")
			var zero DeactivateTraceIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(86), raw)
			if err != nil {
				var empty s00.EUTRANTraceID
				return empty, runtime.WrapDecodePath(err, "EUTRANTraceID")
			}
			value, ok := decoded.AsEUTRANTraceID()
			if !ok {
				var empty s00.EUTRANTraceID
				return empty, fmt.Errorf("binding DeactivateTraceIEs.id-E-UTRAN-Trace-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEUTRANTraceIDValueCodecFieldEncode(&sealed) = func(value s00.EUTRANTraceID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DeactivateTraceIEValue{id: s00.ProtocolIEID(86), rowEUTRANTraceID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEUTRANTraceIDValueCodecFieldCapture(&sealed) = func(v s00.EUTRANTraceID, options aper.DecodeState) (s00.EUTRANTraceID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEUTRANTraceID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEUTRANTraceIDValueCodecFieldCompare(&sealed) = func(v s00.EUTRANTraceID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEUTRANTraceID(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeEUTRANTraceIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANTraceID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EUTRANTraceID) DeactivateTraceIEValue {
			return DeactivateTraceIEValue{id: s00.ProtocolIEID(86), rowEUTRANTraceID: &value}
		}, get: func(value *DeactivateTraceIEValue) (*s00.EUTRANTraceID, bool) { return value.AsEUTRANTraceID() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DeactivateTraceIETable.
func (t DeactivateTraceIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (DeactivateTraceIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(86):
		return DeactivateTraceIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-UTRAN-Trace-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DeactivateTraceIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DeactivateTraceIEField{}, aper.OperationError(err, "Opaque")
		}
		return DeactivateTraceIEField{Id: id, Criticality: criticality, Value: DeactivateTraceIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type DownlinkNonUEAssociatedLPPaTransportIETable struct{}

func DownlinkNonUEAssociatedLPPaTransportIEs() DownlinkNonUEAssociatedLPPaTransportIETable {
	return DownlinkNonUEAssociatedLPPaTransportIETable{}
}

// ID returns the ASN.1 object-set identity of DownlinkNonUEAssociatedLPPaTransportIETable.
func (DownlinkNonUEAssociatedLPPaTransportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNonUEAssociatedLPPaTransport-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DownlinkNonUEAssociatedLPPaTransportIETable.
func (DownlinkNonUEAssociatedLPPaTransportIETable) Table() s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable {
	return func() s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable {
		sealed := s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable{}
		*s00.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (DownlinkNonUEAssociatedLPPaTransportIETable) infoRoutingID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNonUEAssociatedLPPaTransportIEs().ID(), ID: s00.ProtocolIEID(148), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Routing-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNonUEAssociatedLPPaTransport-IEs", Row: "id-Routing-ID"}}}
}

// RoutingID returns the typed binding for the RoutingID row of DownlinkNonUEAssociatedLPPaTransportIETable.
func (t DownlinkNonUEAssociatedLPPaTransportIETable) RoutingID() DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding {
	return DownlinkNonUEAssociatedLPPaTransportRoutingIDIEBinding{info: t.infoRoutingID(), codec: func() s02.RoutingIDValueCodec {
		sealed := s02.RoutingIDValueCodec{}
		*s02.BridgeRoutingIDValueCodecFieldPath(&sealed) = "RoutingID"
		*s02.BridgeRoutingIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RoutingID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RoutingID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RoutingID")
			var zero DownlinkNonUEAssociatedLPPaTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(148), raw)
			if err != nil {
				var empty s00.RoutingID
				return empty, runtime.WrapDecodePath(err, "RoutingID")
			}
			value, ok := decoded.AsRoutingID()
			if !ok {
				var empty s00.RoutingID
				return empty, fmt.Errorf("binding DownlinkNonUEAssociatedLPPaTransport-IEs.id-Routing-ID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeRoutingIDValueCodecFieldEncode(&sealed) = func(value s00.RoutingID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNonUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(148), rowRoutingID: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeRoutingIDValueCodecFieldCapture(&sealed) = func(v s00.RoutingID, options aper.DecodeState) (s00.RoutingID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APRoutingID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeRoutingIDValueCodecFieldCompare(&sealed) = func(v s00.RoutingID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRoutingID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeRoutingIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RoutingID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RoutingID) DownlinkNonUEAssociatedLPPaTransportIEValue {
			return DownlinkNonUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(148), rowRoutingID: &value}
		}, get: func(value *DownlinkNonUEAssociatedLPPaTransportIEValue) (*s00.RoutingID, bool) {
			return value.AsRoutingID()
		}}
}
func (DownlinkNonUEAssociatedLPPaTransportIETable) infoLPPaPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNonUEAssociatedLPPaTransportIEs().ID(), ID: s00.ProtocolIEID(147), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LPPa-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNonUEAssociatedLPPaTransport-IEs", Row: "id-LPPa-PDU"}}}
}

// LPPaPDU returns the typed binding for the LPPaPDU row of DownlinkNonUEAssociatedLPPaTransportIETable.
func (t DownlinkNonUEAssociatedLPPaTransportIETable) LPPaPDU() DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding {
	return DownlinkNonUEAssociatedLPPaTransportLPPaPDUIEBinding{info: t.infoLPPaPDU(), codec: func() s01.LPPaPDUValueCodec {
		sealed := s01.LPPaPDUValueCodec{}
		*s01.BridgeLPPaPDUValueCodecFieldPath(&sealed) = "LPPaPDU"
		*s01.BridgeLPPaPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LPPaPDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.LPPaPDU
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LPPaPDU")
			var zero DownlinkNonUEAssociatedLPPaTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(147), raw)
			if err != nil {
				var empty s00.LPPaPDU
				return empty, runtime.WrapDecodePath(err, "LPPaPDU")
			}
			value, ok := decoded.AsLPPaPDU()
			if !ok {
				var empty s00.LPPaPDU
				return empty, fmt.Errorf("binding DownlinkNonUEAssociatedLPPaTransport-IEs.id-LPPa-PDU: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeLPPaPDUValueCodecFieldEncode(&sealed) = func(value s00.LPPaPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNonUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(147), rowLPPaPDU: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeLPPaPDUValueCodecFieldCapture(&sealed) = func(v s00.LPPaPDU, options aper.DecodeState) (s00.LPPaPDU, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APLPPaPDU(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeLPPaPDUValueCodecFieldCompare(&sealed) = func(v s00.LPPaPDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APLPPaPDU(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLPPaPDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LPPaPDU"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.LPPaPDU) DownlinkNonUEAssociatedLPPaTransportIEValue {
			return DownlinkNonUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(147), rowLPPaPDU: &value}
		}, get: func(value *DownlinkNonUEAssociatedLPPaTransportIEValue) (*s00.LPPaPDU, bool) {
			return value.AsLPPaPDU()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DownlinkNonUEAssociatedLPPaTransportIETable.
func (t DownlinkNonUEAssociatedLPPaTransportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (DownlinkNonUEAssociatedLPPaTransportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(148):
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-Routing-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(147):
		return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-LPPa-PDU requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		return DownlinkNonUEAssociatedLPPaTransportIEField{Id: id, Criticality: criticality, Value: DownlinkNonUEAssociatedLPPaTransportIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type DownlinkUEAssociatedLPPaTransportIETable struct{}

func DownlinkUEAssociatedLPPaTransportIEs() DownlinkUEAssociatedLPPaTransportIETable {
	return DownlinkUEAssociatedLPPaTransportIETable{}
}

// ID returns the ASN.1 object-set identity of DownlinkUEAssociatedLPPaTransportIETable.
func (DownlinkUEAssociatedLPPaTransportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkUEAssociatedLPPaTransport-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DownlinkUEAssociatedLPPaTransportIETable.
func (DownlinkUEAssociatedLPPaTransportIETable) Table() s00.DownlinkUEAssociatedLPPaTransportIEValueIETable {
	return func() s00.DownlinkUEAssociatedLPPaTransportIEValueIETable {
		sealed := s00.DownlinkUEAssociatedLPPaTransportIEValueIETable{}
		*s00.BridgeDownlinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (DownlinkUEAssociatedLPPaTransportIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkUEAssociatedLPPaTransportIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkUEAssociatedLPPaTransport-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of DownlinkUEAssociatedLPPaTransportIETable.
func (t DownlinkUEAssociatedLPPaTransportIETable) MMEUES1APID() DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding {
	return DownlinkUEAssociatedLPPaTransportMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero DownlinkUEAssociatedLPPaTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding DownlinkUEAssociatedLPPaTransport-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) DownlinkUEAssociatedLPPaTransportIEValue {
			return DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *DownlinkUEAssociatedLPPaTransportIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (DownlinkUEAssociatedLPPaTransportIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkUEAssociatedLPPaTransportIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkUEAssociatedLPPaTransport-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of DownlinkUEAssociatedLPPaTransportIETable.
func (t DownlinkUEAssociatedLPPaTransportIETable) ENBUES1APID() DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding {
	return DownlinkUEAssociatedLPPaTransportENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero DownlinkUEAssociatedLPPaTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding DownlinkUEAssociatedLPPaTransport-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) DownlinkUEAssociatedLPPaTransportIEValue {
			return DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *DownlinkUEAssociatedLPPaTransportIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (DownlinkUEAssociatedLPPaTransportIETable) infoRoutingID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkUEAssociatedLPPaTransportIEs().ID(), ID: s00.ProtocolIEID(148), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Routing-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkUEAssociatedLPPaTransport-IEs", Row: "id-Routing-ID"}}}
}

// RoutingID returns the typed binding for the RoutingID row of DownlinkUEAssociatedLPPaTransportIETable.
func (t DownlinkUEAssociatedLPPaTransportIETable) RoutingID() DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding {
	return DownlinkUEAssociatedLPPaTransportRoutingIDIEBinding{info: t.infoRoutingID(), codec: func() s02.RoutingIDValueCodec {
		sealed := s02.RoutingIDValueCodec{}
		*s02.BridgeRoutingIDValueCodecFieldPath(&sealed) = "RoutingID"
		*s02.BridgeRoutingIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RoutingID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RoutingID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RoutingID")
			var zero DownlinkUEAssociatedLPPaTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(148), raw)
			if err != nil {
				var empty s00.RoutingID
				return empty, runtime.WrapDecodePath(err, "RoutingID")
			}
			value, ok := decoded.AsRoutingID()
			if !ok {
				var empty s00.RoutingID
				return empty, fmt.Errorf("binding DownlinkUEAssociatedLPPaTransport-IEs.id-Routing-ID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeRoutingIDValueCodecFieldEncode(&sealed) = func(value s00.RoutingID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(148), rowRoutingID: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeRoutingIDValueCodecFieldCapture(&sealed) = func(v s00.RoutingID, options aper.DecodeState) (s00.RoutingID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APRoutingID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeRoutingIDValueCodecFieldCompare(&sealed) = func(v s00.RoutingID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRoutingID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeRoutingIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RoutingID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RoutingID) DownlinkUEAssociatedLPPaTransportIEValue {
			return DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(148), rowRoutingID: &value}
		}, get: func(value *DownlinkUEAssociatedLPPaTransportIEValue) (*s00.RoutingID, bool) {
			return value.AsRoutingID()
		}}
}
func (DownlinkUEAssociatedLPPaTransportIETable) infoLPPaPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkUEAssociatedLPPaTransportIEs().ID(), ID: s00.ProtocolIEID(147), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LPPa-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkUEAssociatedLPPaTransport-IEs", Row: "id-LPPa-PDU"}}}
}

// LPPaPDU returns the typed binding for the LPPaPDU row of DownlinkUEAssociatedLPPaTransportIETable.
func (t DownlinkUEAssociatedLPPaTransportIETable) LPPaPDU() DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding {
	return DownlinkUEAssociatedLPPaTransportLPPaPDUIEBinding{info: t.infoLPPaPDU(), codec: func() s01.LPPaPDUValueCodec {
		sealed := s01.LPPaPDUValueCodec{}
		*s01.BridgeLPPaPDUValueCodecFieldPath(&sealed) = "LPPaPDU"
		*s01.BridgeLPPaPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LPPaPDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.LPPaPDU
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LPPaPDU")
			var zero DownlinkUEAssociatedLPPaTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(147), raw)
			if err != nil {
				var empty s00.LPPaPDU
				return empty, runtime.WrapDecodePath(err, "LPPaPDU")
			}
			value, ok := decoded.AsLPPaPDU()
			if !ok {
				var empty s00.LPPaPDU
				return empty, fmt.Errorf("binding DownlinkUEAssociatedLPPaTransport-IEs.id-LPPa-PDU: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeLPPaPDUValueCodecFieldEncode(&sealed) = func(value s00.LPPaPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(147), rowLPPaPDU: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeLPPaPDUValueCodecFieldCapture(&sealed) = func(v s00.LPPaPDU, options aper.DecodeState) (s00.LPPaPDU, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APLPPaPDU(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeLPPaPDUValueCodecFieldCompare(&sealed) = func(v s00.LPPaPDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APLPPaPDU(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLPPaPDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LPPaPDU"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.LPPaPDU) DownlinkUEAssociatedLPPaTransportIEValue {
			return DownlinkUEAssociatedLPPaTransportIEValue{id: s00.ProtocolIEID(147), rowLPPaPDU: &value}
		}, get: func(value *DownlinkUEAssociatedLPPaTransportIEValue) (*s00.LPPaPDU, bool) { return value.AsLPPaPDU() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DownlinkUEAssociatedLPPaTransportIETable.
func (t DownlinkUEAssociatedLPPaTransportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (DownlinkUEAssociatedLPPaTransportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(148):
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-Routing-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(147):
		return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-LPPa-PDU requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		return DownlinkUEAssociatedLPPaTransportIEField{Id: id, Criticality: criticality, Value: DownlinkUEAssociatedLPPaTransportIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// EHRPDCapacityValueCodec binds the complete source value type.
func EHRPDCapacityValueCodec() s00.EHRPDCapacityValueValueCodec {
	return func() s00.EHRPDCapacityValueValueCodec {
		sealed := s00.EHRPDCapacityValueValueCodec{}
		*s00.BridgeEHRPDCapacityValueValueCodecFieldPath(&sealed) = "EHRPDCapacityValue"
		*s00.BridgeEHRPDCapacityValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EHRPDCapacityValue, error) {
			var zero s00.EHRPDCapacityValue
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EHRPDCapacityValue, error) {
				var v struct{ Value s00.EHRPDCapacityValue }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(100), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.EHRPDCapacityValue(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EHRPDCapacityValue"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEHRPDCapacityValueValueCodecFieldEncode(&sealed) = func(value s00.EHRPDCapacityValue, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EHRPDCapacityValue, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.EHRPDCapacityValue }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(100), false); err != nil {
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
		*s00.BridgeEHRPDCapacityValueValueCodecFieldCapture(&sealed) = func(v s00.EHRPDCapacityValue, options aper.DecodeState) (s00.EHRPDCapacityValue, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEHRPDCapacityValue(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s00.BridgeEHRPDCapacityValueValueCodecFieldCompare(&sealed) = func(v s00.EHRPDCapacityValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEHRPDCapacityValue(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEHRPDCapacityValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EHRPDCapacityValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldCapture(v *CellBasedQMCExtIEsExtFieldValueCodec) *func(s08.CellBasedQMCExtIEsExtField, aper.DecodeState) (s08.CellBasedQMCExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldCompare(v *CellBasedQMCExtIEsExtFieldValueCodec) *func(s08.CellBasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldContext(v *CellBasedQMCExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldDecode(v *CellBasedQMCExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (s08.CellBasedQMCExtIEsExtField, error) {
	return &v.decode
}
func BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldEncode(v *CellBasedQMCExtIEsExtFieldValueCodec) *func(s08.CellBasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldPath(v *CellBasedQMCExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldCapture(v *CellIDBroadcastItemExtIEsExtContainerValueCodec) *func(CellIDBroadcastItemExtIEsExtContainer, aper.DecodeState) (CellIDBroadcastItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldCompare(v *CellIDBroadcastItemExtIEsExtContainerValueCodec) *func(CellIDBroadcastItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldContext(v *CellIDBroadcastItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldDecode(v *CellIDBroadcastItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CellIDBroadcastItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldEncode(v *CellIDBroadcastItemExtIEsExtContainerValueCodec) *func(CellIDBroadcastItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldPath(v *CellIDBroadcastItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIDBroadcastItemExtIEsExtFieldFieldReplay(v *CellIDBroadcastItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCellIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v *CellIDBroadcastItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCellIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(v *CellIDBroadcastItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CellIDBroadcastItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldCapture(v *CellIDBroadcastItemExtIEsExtFieldValueCodec) *func(CellIDBroadcastItemExtIEsExtField, aper.DecodeState) (CellIDBroadcastItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldCompare(v *CellIDBroadcastItemExtIEsExtFieldValueCodec) *func(CellIDBroadcastItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldContext(v *CellIDBroadcastItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldDecode(v *CellIDBroadcastItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CellIDBroadcastItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldEncode(v *CellIDBroadcastItemExtIEsExtFieldValueCodec) *func(CellIDBroadcastItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldPath(v *CellIDBroadcastItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldCapture(v *CellIDCancelledItemExtIEsExtContainerValueCodec) *func(CellIDCancelledItemExtIEsExtContainer, aper.DecodeState) (CellIDCancelledItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldCompare(v *CellIDCancelledItemExtIEsExtContainerValueCodec) *func(CellIDCancelledItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldContext(v *CellIDCancelledItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldDecode(v *CellIDCancelledItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CellIDCancelledItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldEncode(v *CellIDCancelledItemExtIEsExtContainerValueCodec) *func(CellIDCancelledItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldPath(v *CellIDCancelledItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIDCancelledItemExtIEsExtFieldFieldReplay(v *CellIDCancelledItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCellIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v *CellIDCancelledItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCellIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(v *CellIDCancelledItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CellIDCancelledItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldCapture(v *CellIDCancelledItemExtIEsExtFieldValueCodec) *func(CellIDCancelledItemExtIEsExtField, aper.DecodeState) (CellIDCancelledItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldCompare(v *CellIDCancelledItemExtIEsExtFieldValueCodec) *func(CellIDCancelledItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldContext(v *CellIDCancelledItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldDecode(v *CellIDCancelledItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CellIDCancelledItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldEncode(v *CellIDCancelledItemExtIEsExtFieldValueCodec) *func(CellIDCancelledItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldPath(v *CellIDCancelledItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldCapture(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) *func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldCompare(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) *func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldContext(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldDecode(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldEncode(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) *func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldPath(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldReplay(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldCapture(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) *func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldCompare(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) *func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldContext(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldDecode(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, error) {
	return &v.decode
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldEncode(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) *func(CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldPath(v *CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTypeExtIEsExtContainerValueCodecFieldCapture(v *CellTypeExtIEsExtContainerValueCodec) *func(CellTypeExtIEsExtContainer, aper.DecodeState) (CellTypeExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTypeExtIEsExtContainerValueCodecFieldCompare(v *CellTypeExtIEsExtContainerValueCodec) *func(CellTypeExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTypeExtIEsExtContainerValueCodecFieldContext(v *CellTypeExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTypeExtIEsExtContainerValueCodecFieldDecode(v *CellTypeExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CellTypeExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCellTypeExtIEsExtContainerValueCodecFieldEncode(v *CellTypeExtIEsExtContainerValueCodec) *func(CellTypeExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTypeExtIEsExtContainerValueCodecFieldPath(v *CellTypeExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTypeExtIEsExtFieldFieldReplay(v *CellTypeExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCellTypeExtIEsExtFieldFieldWithoutReplay(v *CellTypeExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCellTypeExtIEsExtFieldMethodMarshalAPERTo(v *CellTypeExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellTypeExtIEsExtFieldMethodUnmarshalAPERFrom(v *CellTypeExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellTypeExtIEsExtFieldValueCodecFieldCapture(v *CellTypeExtIEsExtFieldValueCodec) *func(CellTypeExtIEsExtField, aper.DecodeState) (CellTypeExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTypeExtIEsExtFieldValueCodecFieldCompare(v *CellTypeExtIEsExtFieldValueCodec) *func(CellTypeExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTypeExtIEsExtFieldValueCodecFieldContext(v *CellTypeExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTypeExtIEsExtFieldValueCodecFieldDecode(v *CellTypeExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CellTypeExtIEsExtField, error) {
	return &v.decode
}
func BridgeCellTypeExtIEsExtFieldValueCodecFieldEncode(v *CellTypeExtIEsExtFieldValueCodec) *func(CellTypeExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTypeExtIEsExtFieldValueCodecFieldPath(v *CellTypeExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldCapture(v *CompletedCellinEAIItemExtIEsExtContainerValueCodec) *func(CompletedCellinEAIItemExtIEsExtContainer, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldCompare(v *CompletedCellinEAIItemExtIEsExtContainerValueCodec) *func(CompletedCellinEAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldContext(v *CompletedCellinEAIItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldDecode(v *CompletedCellinEAIItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldEncode(v *CompletedCellinEAIItemExtIEsExtContainerValueCodec) *func(CompletedCellinEAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldPath(v *CompletedCellinEAIItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldFieldReplay(v *CompletedCellinEAIItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v *CompletedCellinEAIItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(v *CompletedCellinEAIItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CompletedCellinEAIItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldCapture(v *CompletedCellinEAIItemExtIEsExtFieldValueCodec) *func(CompletedCellinEAIItemExtIEsExtField, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldCompare(v *CompletedCellinEAIItemExtIEsExtFieldValueCodec) *func(CompletedCellinEAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldContext(v *CompletedCellinEAIItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldDecode(v *CompletedCellinEAIItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CompletedCellinEAIItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldEncode(v *CompletedCellinEAIItemExtIEsExtFieldValueCodec) *func(CompletedCellinEAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldPath(v *CompletedCellinEAIItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldCapture(v *CompletedCellinTAIItemExtIEsExtContainerValueCodec) *func(CompletedCellinTAIItemExtIEsExtContainer, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldCompare(v *CompletedCellinTAIItemExtIEsExtContainerValueCodec) *func(CompletedCellinTAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldContext(v *CompletedCellinTAIItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldDecode(v *CompletedCellinTAIItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldEncode(v *CompletedCellinTAIItemExtIEsExtContainerValueCodec) *func(CompletedCellinTAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldPath(v *CompletedCellinTAIItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldFieldReplay(v *CompletedCellinTAIItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v *CompletedCellinTAIItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(v *CompletedCellinTAIItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CompletedCellinTAIItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldCapture(v *CompletedCellinTAIItemExtIEsExtFieldValueCodec) *func(CompletedCellinTAIItemExtIEsExtField, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldCompare(v *CompletedCellinTAIItemExtIEsExtFieldValueCodec) *func(CompletedCellinTAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldContext(v *CompletedCellinTAIItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldDecode(v *CompletedCellinTAIItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CompletedCellinTAIItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldEncode(v *CompletedCellinTAIItemExtIEsExtFieldValueCodec) *func(CompletedCellinTAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldPath(v *CompletedCellinTAIItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldCapture(v *ConnectedengNBItemExtIEsExtContainerValueCodec) *func(ConnectedengNBItemExtIEsExtContainer, aper.DecodeState) (ConnectedengNBItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldCompare(v *ConnectedengNBItemExtIEsExtContainerValueCodec) *func(ConnectedengNBItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldContext(v *ConnectedengNBItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldDecode(v *ConnectedengNBItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ConnectedengNBItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldEncode(v *ConnectedengNBItemExtIEsExtContainerValueCodec) *func(ConnectedengNBItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldPath(v *ConnectedengNBItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectedengNBItemExtIEsExtFieldFieldReplay(v *ConnectedengNBItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectedengNBItemExtIEsExtFieldFieldWithoutReplay(v *ConnectedengNBItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeConnectedengNBItemExtIEsExtFieldMethodMarshalAPERTo(v *ConnectedengNBItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeConnectedengNBItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ConnectedengNBItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldCapture(v *ConnectedengNBItemExtIEsExtFieldValueCodec) *func(ConnectedengNBItemExtIEsExtField, aper.DecodeState) (ConnectedengNBItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldCompare(v *ConnectedengNBItemExtIEsExtFieldValueCodec) *func(ConnectedengNBItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldContext(v *ConnectedengNBItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldDecode(v *ConnectedengNBItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ConnectedengNBItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldEncode(v *ConnectedengNBItemExtIEsExtFieldValueCodec) *func(ConnectedengNBItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldPath(v *ConnectedengNBItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeContextatSourceExtIEsExtContainerValueCodecFieldCapture(v *ContextatSourceExtIEsExtContainerValueCodec) *func(ContextatSourceExtIEsExtContainer, aper.DecodeState) (ContextatSourceExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeContextatSourceExtIEsExtContainerValueCodecFieldCompare(v *ContextatSourceExtIEsExtContainerValueCodec) *func(ContextatSourceExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeContextatSourceExtIEsExtContainerValueCodecFieldContext(v *ContextatSourceExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeContextatSourceExtIEsExtContainerValueCodecFieldDecode(v *ContextatSourceExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ContextatSourceExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeContextatSourceExtIEsExtContainerValueCodecFieldEncode(v *ContextatSourceExtIEsExtContainerValueCodec) *func(ContextatSourceExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeContextatSourceExtIEsExtContainerValueCodecFieldPath(v *ContextatSourceExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeContextatSourceExtIEsExtFieldFieldReplay(v *ContextatSourceExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeContextatSourceExtIEsExtFieldFieldWithoutReplay(v *ContextatSourceExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeContextatSourceExtIEsExtFieldMethodMarshalAPERTo(v *ContextatSourceExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeContextatSourceExtIEsExtFieldMethodUnmarshalAPERFrom(v *ContextatSourceExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeContextatSourceExtIEsExtFieldValueCodecFieldCapture(v *ContextatSourceExtIEsExtFieldValueCodec) *func(ContextatSourceExtIEsExtField, aper.DecodeState) (ContextatSourceExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeContextatSourceExtIEsExtFieldValueCodecFieldCompare(v *ContextatSourceExtIEsExtFieldValueCodec) *func(ContextatSourceExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeContextatSourceExtIEsExtFieldValueCodecFieldContext(v *ContextatSourceExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeContextatSourceExtIEsExtFieldValueCodecFieldDecode(v *ContextatSourceExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ContextatSourceExtIEsExtField, error) {
	return &v.decode
}
func BridgeContextatSourceExtIEsExtFieldValueCodecFieldEncode(v *ContextatSourceExtIEsExtFieldValueCodec) *func(ContextatSourceExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeContextatSourceExtIEsExtFieldValueCodecFieldPath(v *ContextatSourceExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldCapture(v *CriticalityDiagnosticsExtIEsExtContainerValueCodec) *func(CriticalityDiagnosticsExtIEsExtContainer, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldCompare(v *CriticalityDiagnosticsExtIEsExtContainerValueCodec) *func(CriticalityDiagnosticsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldContext(v *CriticalityDiagnosticsExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldDecode(v *CriticalityDiagnosticsExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldEncode(v *CriticalityDiagnosticsExtIEsExtContainerValueCodec) *func(CriticalityDiagnosticsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldPath(v *CriticalityDiagnosticsExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v *CriticalityDiagnosticsExtIEsExtField) *aper.Snapshot {
	return &v.replay
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
func BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldCapture(v *CriticalityDiagnosticsExtIEsExtFieldValueCodec) *func(CriticalityDiagnosticsExtIEsExtField, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldCompare(v *CriticalityDiagnosticsExtIEsExtFieldValueCodec) *func(CriticalityDiagnosticsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldContext(v *CriticalityDiagnosticsExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldDecode(v *CriticalityDiagnosticsExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsExtIEsExtField, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldEncode(v *CriticalityDiagnosticsExtIEsExtFieldValueCodec) *func(CriticalityDiagnosticsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldPath(v *CriticalityDiagnosticsExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldCapture(v *CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) *func(CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldCompare(v *CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) *func(CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldContext(v *CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldDecode(v *CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldEncode(v *CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) *func(CriticalityDiagnosticsIEItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldPath(v *CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldReplay(v *CriticalityDiagnosticsIEItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldWithoutReplay(v *CriticalityDiagnosticsIEItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodMarshalAPERTo(v *CriticalityDiagnosticsIEItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldCapture(v *CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) *func(CriticalityDiagnosticsIEItemExtIEsExtField, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldCompare(v *CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) *func(CriticalityDiagnosticsIEItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldContext(v *CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldDecode(v *CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldEncode(v *CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) *func(CriticalityDiagnosticsIEItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldPath(v *CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldCapture(v *DAPSRequestInfoExtIEsExtContainerValueCodec) *func(DAPSRequestInfoExtIEsExtContainer, aper.DecodeState) (DAPSRequestInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldCompare(v *DAPSRequestInfoExtIEsExtContainerValueCodec) *func(DAPSRequestInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldContext(v *DAPSRequestInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldDecode(v *DAPSRequestInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (DAPSRequestInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldEncode(v *DAPSRequestInfoExtIEsExtContainerValueCodec) *func(DAPSRequestInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldPath(v *DAPSRequestInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSRequestInfoExtIEsExtFieldFieldReplay(v *DAPSRequestInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSRequestInfoExtIEsExtFieldFieldWithoutReplay(v *DAPSRequestInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeDAPSRequestInfoExtIEsExtFieldMethodMarshalAPERTo(v *DAPSRequestInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSRequestInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *DAPSRequestInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldCapture(v *DAPSRequestInfoExtIEsExtFieldValueCodec) *func(DAPSRequestInfoExtIEsExtField, aper.DecodeState) (DAPSRequestInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldCompare(v *DAPSRequestInfoExtIEsExtFieldValueCodec) *func(DAPSRequestInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldContext(v *DAPSRequestInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldDecode(v *DAPSRequestInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (DAPSRequestInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldEncode(v *DAPSRequestInfoExtIEsExtFieldValueCodec) *func(DAPSRequestInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldPath(v *DAPSRequestInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldCapture(v *DAPSResponseInfoExtIEsExtContainerValueCodec) *func(DAPSResponseInfoExtIEsExtContainer, aper.DecodeState) (DAPSResponseInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldCompare(v *DAPSResponseInfoExtIEsExtContainerValueCodec) *func(DAPSResponseInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldContext(v *DAPSResponseInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldDecode(v *DAPSResponseInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldEncode(v *DAPSResponseInfoExtIEsExtContainerValueCodec) *func(DAPSResponseInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldPath(v *DAPSResponseInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoExtIEsExtFieldFieldReplay(v *DAPSResponseInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoExtIEsExtFieldFieldWithoutReplay(v *DAPSResponseInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoExtIEsExtFieldMethodMarshalAPERTo(v *DAPSResponseInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSResponseInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *DAPSResponseInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldCapture(v *DAPSResponseInfoExtIEsExtFieldValueCodec) *func(DAPSResponseInfoExtIEsExtField, aper.DecodeState) (DAPSResponseInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldCompare(v *DAPSResponseInfoExtIEsExtFieldValueCodec) *func(DAPSResponseInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldContext(v *DAPSResponseInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldDecode(v *DAPSResponseInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldEncode(v *DAPSResponseInfoExtIEsExtFieldValueCodec) *func(DAPSResponseInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldPath(v *DAPSResponseInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldCapture(v *DAPSResponseInfoItemExtIEsExtContainerValueCodec) *func(DAPSResponseInfoItemExtIEsExtContainer, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldCompare(v *DAPSResponseInfoItemExtIEsExtContainerValueCodec) *func(DAPSResponseInfoItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldContext(v *DAPSResponseInfoItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldDecode(v *DAPSResponseInfoItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldEncode(v *DAPSResponseInfoItemExtIEsExtContainerValueCodec) *func(DAPSResponseInfoItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldPath(v *DAPSResponseInfoItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldFieldReplay(v *DAPSResponseInfoItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldFieldWithoutReplay(v *DAPSResponseInfoItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldMethodMarshalAPERTo(v *DAPSResponseInfoItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *DAPSResponseInfoItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldCapture(v *DAPSResponseInfoItemExtIEsExtFieldValueCodec) *func(DAPSResponseInfoItemExtIEsExtField, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldCompare(v *DAPSResponseInfoItemExtIEsExtFieldValueCodec) *func(DAPSResponseInfoItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldContext(v *DAPSResponseInfoItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldDecode(v *DAPSResponseInfoItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldEncode(v *DAPSResponseInfoItemExtIEsExtFieldValueCodec) *func(DAPSResponseInfoItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldPath(v *DAPSResponseInfoItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldCapture(v *DLCPSecurityInformationExtIEsExtContainerValueCodec) *func(DLCPSecurityInformationExtIEsExtContainer, aper.DecodeState) (DLCPSecurityInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldCompare(v *DLCPSecurityInformationExtIEsExtContainerValueCodec) *func(DLCPSecurityInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldContext(v *DLCPSecurityInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldDecode(v *DLCPSecurityInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (DLCPSecurityInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldEncode(v *DLCPSecurityInformationExtIEsExtContainerValueCodec) *func(DLCPSecurityInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldPath(v *DLCPSecurityInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDLCPSecurityInformationExtIEsExtFieldFieldReplay(v *DLCPSecurityInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeDLCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v *DLCPSecurityInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeDLCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(v *DLCPSecurityInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDLCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *DLCPSecurityInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldCapture(v *DLCPSecurityInformationExtIEsExtFieldValueCodec) *func(DLCPSecurityInformationExtIEsExtField, aper.DecodeState) (DLCPSecurityInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldCompare(v *DLCPSecurityInformationExtIEsExtFieldValueCodec) *func(DLCPSecurityInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldContext(v *DLCPSecurityInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldDecode(v *DLCPSecurityInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (DLCPSecurityInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldEncode(v *DLCPSecurityInformationExtIEsExtFieldValueCodec) *func(DLCPSecurityInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldPath(v *DLCPSecurityInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDeactivateTraceIEContainerValueCodecFieldCapture(v *DeactivateTraceIEContainerValueCodec) *func(DeactivateTraceIEContainer, aper.DecodeState) (DeactivateTraceIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDeactivateTraceIEContainerValueCodecFieldCompare(v *DeactivateTraceIEContainerValueCodec) *func(DeactivateTraceIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDeactivateTraceIEContainerValueCodecFieldContext(v *DeactivateTraceIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDeactivateTraceIEContainerValueCodecFieldDecode(v *DeactivateTraceIEContainerValueCodec) *func([]byte, aper.DecodeState) (DeactivateTraceIEContainer, error) {
	return &v.decode
}
func BridgeDeactivateTraceIEContainerValueCodecFieldEncode(v *DeactivateTraceIEContainerValueCodec) *func(DeactivateTraceIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDeactivateTraceIEContainerValueCodecFieldPath(v *DeactivateTraceIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDeactivateTraceIEFieldFieldReplay(v *DeactivateTraceIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeDeactivateTraceIEFieldFieldWithoutReplay(v *DeactivateTraceIEField) *bool {
	return &v.withoutReplay
}
func BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(v *DeactivateTraceIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(v *DeactivateTraceIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDeactivateTraceIEFieldValueCodecFieldCapture(v *DeactivateTraceIEFieldValueCodec) *func(DeactivateTraceIEField, aper.DecodeState) (DeactivateTraceIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeDeactivateTraceIEFieldValueCodecFieldCompare(v *DeactivateTraceIEFieldValueCodec) *func(DeactivateTraceIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDeactivateTraceIEFieldValueCodecFieldContext(v *DeactivateTraceIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDeactivateTraceIEFieldValueCodecFieldDecode(v *DeactivateTraceIEFieldValueCodec) *func([]byte, aper.DecodeState) (DeactivateTraceIEField, error) {
	return &v.decode
}
func BridgeDeactivateTraceIEFieldValueCodecFieldEncode(v *DeactivateTraceIEFieldValueCodec) *func(DeactivateTraceIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDeactivateTraceIEFieldValueCodecFieldPath(v *DeactivateTraceIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldCapture(v *DeactivateTraceIEValueERABIEContainerListValueCodec) *func(DeactivateTraceIEValueERABIEContainerList, aper.DecodeState) (DeactivateTraceIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldCompare(v *DeactivateTraceIEValueERABIEContainerListValueCodec) *func(DeactivateTraceIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldContext(v *DeactivateTraceIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldDecode(v *DeactivateTraceIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DeactivateTraceIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldEncode(v *DeactivateTraceIEValueERABIEContainerListValueCodec) *func(DeactivateTraceIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldPath(v *DeactivateTraceIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDeactivateTraceIEValueFieldId(v *DeactivateTraceIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeDeactivateTraceIEValueFieldIsOpaque(v *DeactivateTraceIEValue) *bool       { return &v.isOpaque }
func BridgeDeactivateTraceIEValueFieldOpaque(v *DeactivateTraceIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeDeactivateTraceIEValueFieldRowENBUES1APID(v *DeactivateTraceIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeDeactivateTraceIEValueFieldRowEUTRANTraceID(v *DeactivateTraceIEValue) **s00.EUTRANTraceID {
	return &v.rowEUTRANTraceID
}
func BridgeDeactivateTraceIEValueFieldRowMMEUES1APID(v *DeactivateTraceIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeDeactivateTraceIEValueMethodCaptureSemantics(v DeactivateTraceIEValue, a0 aper.SemanticCapture) DeactivateTraceIEValue {
	return v.captureSemantics(a0)
}
func BridgeDeactivateTraceIEValueMethodCompareSemantics(v DeactivateTraceIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeDeactivateTraceIEValueMethodMatchesID(v DeactivateTraceIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeDeactivateTraceIEValueMethodRule(v DeactivateTraceIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) *func(DeactivateTraceIEValueProtocolErrorIEContainerList, aper.DecodeState) (DeactivateTraceIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) *func(DeactivateTraceIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DeactivateTraceIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) *func(DeactivateTraceIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldCapture(v *DeactivateTraceIEValueProtocolIEContainerListValueCodec) *func(DeactivateTraceIEValueProtocolIEContainerList, aper.DecodeState) (DeactivateTraceIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldCompare(v *DeactivateTraceIEValueProtocolIEContainerListValueCodec) *func(DeactivateTraceIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldContext(v *DeactivateTraceIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldDecode(v *DeactivateTraceIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DeactivateTraceIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldEncode(v *DeactivateTraceIEValueProtocolIEContainerListValueCodec) *func(DeactivateTraceIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldPath(v *DeactivateTraceIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(v *DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(v *DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(v *DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(v *DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) *func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEContainer, error) {
	return &v.decode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(v *DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldPath(v *DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v *DownlinkNonUEAssociatedLPPaTransportIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v *DownlinkNonUEAssociatedLPPaTransportIEField) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(v *DownlinkNonUEAssociatedLPPaTransportIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(v *DownlinkNonUEAssociatedLPPaTransportIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(v *DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEField, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(v *DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(v *DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(v *DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) *func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEField, error) {
	return &v.decode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(v *DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldPath(v *DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(v *DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(v *DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(v *DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(v *DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(v *DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldPath(v *DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldId(v *DownlinkNonUEAssociatedLPPaTransportIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldIsOpaque(v *DownlinkNonUEAssociatedLPPaTransportIEValue) *bool {
	return &v.isOpaque
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldOpaque(v *DownlinkNonUEAssociatedLPPaTransportIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(v *DownlinkNonUEAssociatedLPPaTransportIEValue) **s00.LPPaPDU {
	return &v.rowLPPaPDU
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldRowRoutingID(v *DownlinkNonUEAssociatedLPPaTransportIEValue) **s00.RoutingID {
	return &v.rowRoutingID
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v DownlinkNonUEAssociatedLPPaTransportIEValue, a0 aper.SemanticCapture) DownlinkNonUEAssociatedLPPaTransportIEValue {
	return v.captureSemantics(a0)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v DownlinkNonUEAssociatedLPPaTransportIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodMatchesID(v DownlinkNonUEAssociatedLPPaTransportIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodRule(v DownlinkNonUEAssociatedLPPaTransportIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldPath(v *DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(v *DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEContainer, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(v *DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(v *DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(v *DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) *func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEContainer, error) {
	return &v.decode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(v *DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldPath(v *DownlinkUEAssociatedLPPaTransportIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldReplay(v *DownlinkUEAssociatedLPPaTransportIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v *DownlinkUEAssociatedLPPaTransportIEField) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(v *DownlinkUEAssociatedLPPaTransportIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(v *DownlinkUEAssociatedLPPaTransportIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(v *DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEField, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(v *DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(v *DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(v *DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) *func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEField, error) {
	return &v.decode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(v *DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldPath(v *DownlinkUEAssociatedLPPaTransportIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(v *DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(v *DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(v *DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(v *DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(v *DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldPath(v *DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(v *DownlinkUEAssociatedLPPaTransportIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldIsOpaque(v *DownlinkUEAssociatedLPPaTransportIEValue) *bool {
	return &v.isOpaque
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldOpaque(v *DownlinkUEAssociatedLPPaTransportIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowENBUES1APID(v *DownlinkUEAssociatedLPPaTransportIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(v *DownlinkUEAssociatedLPPaTransportIEValue) **s00.LPPaPDU {
	return &v.rowLPPaPDU
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowMMEUES1APID(v *DownlinkUEAssociatedLPPaTransportIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowRoutingID(v *DownlinkUEAssociatedLPPaTransportIEValue) **s00.RoutingID {
	return &v.rowRoutingID
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v DownlinkUEAssociatedLPPaTransportIEValue, a0 aper.SemanticCapture) DownlinkUEAssociatedLPPaTransportIEValue {
	return v.captureSemantics(a0)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v DownlinkUEAssociatedLPPaTransportIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodMatchesID(v DownlinkUEAssociatedLPPaTransportIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodRule(v DownlinkUEAssociatedLPPaTransportIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldPath(v *DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCapture(v *ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCompare(v *ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldContext(v *ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldDecode(v *ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldEncode(v *ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBStatusTransferTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldPath(v *ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldReplay(v *ENBStatusTransferTransparentContainerExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldWithoutReplay(v *ENBStatusTransferTransparentContainerExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(v *ENBStatusTransferTransparentContainerExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENBStatusTransferTransparentContainerExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCapture(v *ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBStatusTransferTransparentContainerExtIEsExtField, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCompare(v *ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldContext(v *ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldDecode(v *ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferTransparentContainerExtIEsExtField, error) {
	return &v.decode
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldEncode(v *ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBStatusTransferTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldPath(v *ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldCapture(v *ENBX2ExtTLAExtIEsExtContainerValueCodec) *func(ENBX2ExtTLAExtIEsExtContainer, aper.DecodeState) (ENBX2ExtTLAExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldCompare(v *ENBX2ExtTLAExtIEsExtContainerValueCodec) *func(ENBX2ExtTLAExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldContext(v *ENBX2ExtTLAExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldDecode(v *ENBX2ExtTLAExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENBX2ExtTLAExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldEncode(v *ENBX2ExtTLAExtIEsExtContainerValueCodec) *func(ENBX2ExtTLAExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldPath(v *ENBX2ExtTLAExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBX2ExtTLAExtIEsExtFieldFieldReplay(v *ENBX2ExtTLAExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBX2ExtTLAExtIEsExtFieldFieldWithoutReplay(v *ENBX2ExtTLAExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENBX2ExtTLAExtIEsExtFieldMethodMarshalAPERTo(v *ENBX2ExtTLAExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBX2ExtTLAExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENBX2ExtTLAExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldCapture(v *ENBX2ExtTLAExtIEsExtFieldValueCodec) *func(ENBX2ExtTLAExtIEsExtField, aper.DecodeState) (ENBX2ExtTLAExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldCompare(v *ENBX2ExtTLAExtIEsExtFieldValueCodec) *func(ENBX2ExtTLAExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldContext(v *ENBX2ExtTLAExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldDecode(v *ENBX2ExtTLAExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENBX2ExtTLAExtIEsExtField, error) {
	return &v.decode
}
func BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldEncode(v *ENBX2ExtTLAExtIEsExtFieldValueCodec) *func(ENBX2ExtTLAExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldPath(v *ENBX2ExtTLAExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldCapture(v *ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) *func(ENDCSONConfigurationTransferExtIEsExtContainer, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldCompare(v *ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) *func(ENDCSONConfigurationTransferExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldContext(v *ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldDecode(v *ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldEncode(v *ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) *func(ENDCSONConfigurationTransferExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldPath(v *ENDCSONConfigurationTransferExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldReplay(v *ENDCSONConfigurationTransferExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldWithoutReplay(v *ENDCSONConfigurationTransferExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(v *ENDCSONConfigurationTransferExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENDCSONConfigurationTransferExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldCapture(v *ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) *func(ENDCSONConfigurationTransferExtIEsExtField, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldCompare(v *ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) *func(ENDCSONConfigurationTransferExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldContext(v *ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldDecode(v *ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENDCSONConfigurationTransferExtIEsExtField, error) {
	return &v.decode
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldEncode(v *ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) *func(ENDCSONConfigurationTransferExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldPath(v *ENDCSONConfigurationTransferExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldCapture(v *ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) *func(ENDCSONeNBIdentificationExtIEsExtContainer, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldCompare(v *ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) *func(ENDCSONeNBIdentificationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldContext(v *ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldDecode(v *ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldEncode(v *ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) *func(ENDCSONeNBIdentificationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldPath(v *ENDCSONeNBIdentificationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldReplay(v *ENDCSONeNBIdentificationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldWithoutReplay(v *ENDCSONeNBIdentificationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(v *ENDCSONeNBIdentificationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENDCSONeNBIdentificationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldCapture(v *ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) *func(ENDCSONeNBIdentificationExtIEsExtField, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldCompare(v *ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) *func(ENDCSONeNBIdentificationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldContext(v *ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldDecode(v *ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENDCSONeNBIdentificationExtIEsExtField, error) {
	return &v.decode
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldEncode(v *ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) *func(ENDCSONeNBIdentificationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldPath(v *ENDCSONeNBIdentificationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldCapture(v *ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) *func(ENDCSONengNBIdentificationExtIEsExtContainer, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldCompare(v *ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) *func(ENDCSONengNBIdentificationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldContext(v *ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldDecode(v *ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldEncode(v *ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) *func(ENDCSONengNBIdentificationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldPath(v *ENDCSONengNBIdentificationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldReplay(v *ENDCSONengNBIdentificationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldWithoutReplay(v *ENDCSONengNBIdentificationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(v *ENDCSONengNBIdentificationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENDCSONengNBIdentificationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldCapture(v *ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) *func(ENDCSONengNBIdentificationExtIEsExtField, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldCompare(v *ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) *func(ENDCSONengNBIdentificationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldContext(v *ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldDecode(v *ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENDCSONengNBIdentificationExtIEsExtField, error) {
	return &v.decode
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldEncode(v *ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) *func(ENDCSONengNBIdentificationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldPath(v *ENDCSONengNBIdentificationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldCapture(v *ENDCTransferTypeReplyExtIEsExtContainerValueCodec) *func(ENDCTransferTypeReplyExtIEsExtContainer, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldCompare(v *ENDCTransferTypeReplyExtIEsExtContainerValueCodec) *func(ENDCTransferTypeReplyExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldContext(v *ENDCTransferTypeReplyExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldDecode(v *ENDCTransferTypeReplyExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldEncode(v *ENDCTransferTypeReplyExtIEsExtContainerValueCodec) *func(ENDCTransferTypeReplyExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldPath(v *ENDCTransferTypeReplyExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldFieldReplay(v *ENDCTransferTypeReplyExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldFieldWithoutReplay(v *ENDCTransferTypeReplyExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldMethodMarshalAPERTo(v *ENDCTransferTypeReplyExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENDCTransferTypeReplyExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldCapture(v *ENDCTransferTypeReplyExtIEsExtFieldValueCodec) *func(ENDCTransferTypeReplyExtIEsExtField, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldCompare(v *ENDCTransferTypeReplyExtIEsExtFieldValueCodec) *func(ENDCTransferTypeReplyExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldContext(v *ENDCTransferTypeReplyExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldDecode(v *ENDCTransferTypeReplyExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENDCTransferTypeReplyExtIEsExtField, error) {
	return &v.decode
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldEncode(v *ENDCTransferTypeReplyExtIEsExtFieldValueCodec) *func(ENDCTransferTypeReplyExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldPath(v *ENDCTransferTypeReplyExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *DeactivateTraceIEValue) Selected() (any, bool) {
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
	case 86:
		if value, ok := v.AsEUTRANTraceID(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *DownlinkNonUEAssociatedLPPaTransportIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 148:
		if value, ok := v.AsRoutingID(); ok {
			return value, true
		}
	case 147:
		if value, ok := v.AsLPPaPDU(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *DownlinkUEAssociatedLPPaTransportIEValue) Selected() (any, bool) {
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
	case 148:
		if value, ok := v.AsRoutingID(); ok {
			return value, true
		}
	case 147:
		if value, ok := v.AsLPPaPDU(); ok {
			return value, true
		}
	}
	return nil, false
}
