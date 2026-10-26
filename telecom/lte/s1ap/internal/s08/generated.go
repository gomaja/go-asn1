// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s08 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s08

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s04 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// AdditionalGUTIExtIEsExtContainer is ProtocolExtensionContainer {{Additional-GUTI-ExtIEs}} of TS 36.413: a list of AdditionalGUTIExtIEsExtField values.
type AdditionalGUTIExtIEsExtContainer []AdditionalGUTIExtIEsExtField

// AllocationAndRetentionPriorityExtIEsExtContainer is ProtocolExtensionContainer {{AllocationAndRetentionPriority-ExtIEs}} of TS 36.413: a list of AllocationAndRetentionPriorityExtIEsExtField values.
type AllocationAndRetentionPriorityExtIEsExtContainer []AllocationAndRetentionPriorityExtIEsExtField

// AssistanceDataForPagingExtIEsExtContainer is ProtocolExtensionContainer {{AssistanceDataForPaging-ExtIEs}} of TS 36.413: a list of AssistanceDataForPagingExtIEsExtField values.
type AssistanceDataForPagingExtIEsExtContainer []AssistanceDataForPagingExtIEsExtField

// AssistanceDataForRecommendedCellsExtIEsExtContainer is ProtocolExtensionContainer {{AssistanceDataForRecommendedCells-ExtIEs}} of TS 36.413: a list of AssistanceDataForRecommendedCellsExtIEsExtField values.
type AssistanceDataForRecommendedCellsExtIEsExtContainer []AssistanceDataForRecommendedCellsExtIEsExtField

// BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer is ProtocolExtensionContainer {{Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs}} of TS 36.413: a list of BearersSubjectToEarlyStatusTransferItemExtIEsExtField values.
type BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer []BearersSubjectToEarlyStatusTransferItemExtIEsExtField

// BearersSubjectToDLDiscardingItemExtIEsExtContainer is ProtocolExtensionContainer {{Bearers-SubjectToDLDiscarding-ItemExtIEs}} of TS 36.413: a list of BearersSubjectToDLDiscardingItemExtIEsExtField values.
type BearersSubjectToDLDiscardingItemExtIEsExtContainer []BearersSubjectToDLDiscardingItemExtIEsExtField

// BluetoothMeasurementConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{BluetoothMeasurementConfiguration-ExtIEs}} of TS 36.413: a list of BluetoothMeasurementConfigurationExtIEsExtField values.
type BluetoothMeasurementConfigurationExtIEsExtContainer []BluetoothMeasurementConfigurationExtIEsExtField

// CancelledCellinEAIItemExtIEsExtContainer is ProtocolExtensionContainer {{CancelledCellinEAI-Item-ExtIEs}} of TS 36.413: a list of CancelledCellinEAIItemExtIEsExtField values.
type CancelledCellinEAIItemExtIEsExtContainer []CancelledCellinEAIItemExtIEsExtField

// CancelledCellinTAIItemExtIEsExtContainer is ProtocolExtensionContainer {{CancelledCellinTAI-Item-ExtIEs}} of TS 36.413: a list of CancelledCellinTAIItemExtIEsExtField values.
type CancelledCellinTAIItemExtIEsExtContainer []CancelledCellinTAIItemExtIEsExtField

// CellBasedMDTExtIEsExtContainer is ProtocolExtensionContainer {{CellBasedMDT-ExtIEs}} of TS 36.413: a list of CellBasedMDTExtIEsExtField values.
type CellBasedMDTExtIEsExtContainer []CellBasedMDTExtIEsExtField

// CellBasedQMCExtIEsExtContainer is ProtocolExtensionContainer {{CellBasedQMC-ExtIEs}} of TS 36.413: a list of CellBasedQMCExtIEsExtField values.
type CellBasedQMCExtIEsExtContainer []CellBasedQMCExtIEsExtField

// Cdma2000OneXSRVCCInfoExtIEsExtContainer is ProtocolExtensionContainer {{Cdma2000OneXSRVCCInfo-ExtIEs}} of TS 36.413: a list of Cdma2000OneXSRVCCInfoExtIEsExtField values.
type Cdma2000OneXSRVCCInfoExtIEsExtContainer []Cdma2000OneXSRVCCInfoExtIEsExtField

// CGIExtIEsExtContainer is ProtocolExtensionContainer {{CGI-ExtIEs}} of TS 36.413: a list of CGIExtIEsExtField values.
type CGIExtIEsExtContainer []CGIExtIEsExtField

// CNTypeRestrictionsItemExtIEsExtContainer is ProtocolExtensionContainer {{CNTypeRestrictions-Item-ExtIEs}} of TS 36.413: a list of CNTypeRestrictionsItemExtIEsExtField values.
type CNTypeRestrictionsItemExtIEsExtContainer []CNTypeRestrictionsItemExtIEsExtField

// CSGIdListItemExtIEsExtContainer is ProtocolExtensionContainer {{CSG-IdList-Item-ExtIEs}} of TS 36.413: a list of CSGIdListItemExtIEsExtField values.
type CSGIdListItemExtIEsExtContainer []CSGIdListItemExtIEsExtField

// COUNTvalueExtIEsExtContainer is ProtocolExtensionContainer {{COUNTvalue-ExtIEs}} of TS 36.413: a list of COUNTvalueExtIEsExtField values.
type COUNTvalueExtIEsExtContainer []COUNTvalueExtIEsExtField

// COUNTValueExtendedExtIEsExtContainer is ProtocolExtensionContainer {{COUNTValueExtended-ExtIEs}} of TS 36.413: a list of COUNTValueExtendedExtIEsExtField values.
type COUNTValueExtendedExtIEsExtContainer []COUNTValueExtendedExtIEsExtField

// COUNTvaluePDCPSNlength18ExtIEsExtContainer is ProtocolExtensionContainer {{COUNTvaluePDCP-SNlength18-ExtIEs}} of TS 36.413: a list of COUNTvaluePDCPSNlength18ExtIEsExtField values.
type COUNTvaluePDCPSNlength18ExtIEsExtContainer []COUNTvaluePDCPSNlength18ExtIEsExtField

// AdditionalGUTIExtIEsExtField is ProtocolExtensionField {{Additional-GUTI-ExtIEs}} of TS 36.413: an extension field.
type AdditionalGUTIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.AdditionalGUTIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AdditionalGUTIExtIEsExtField) WithoutReplay() AdditionalGUTIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AdditionalGUTIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AdditionalGUTIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAdditionalGUTIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAdditionalGUTIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AdditionalGUTIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AdditionalGUTIExtIEsExtField{}
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
	var zero s03.AdditionalGUTIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAdditionalGUTIExtIEsValueMethodReason(zero, v.Id), s03.BridgeAdditionalGUTIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeAdditionalGUTIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// AllocationAndRetentionPriorityExtIEsExtField is ProtocolExtensionField {{AllocationAndRetentionPriority-ExtIEs}} of TS 36.413: an extension field.
type AllocationAndRetentionPriorityExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.AllocationAndRetentionPriorityExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AllocationAndRetentionPriorityExtIEsExtField) WithoutReplay() AllocationAndRetentionPriorityExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AllocationAndRetentionPriorityExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AllocationAndRetentionPriorityExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AllocationAndRetentionPriorityExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AllocationAndRetentionPriorityExtIEsExtField{}
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
	var zero s03.AllocationAndRetentionPriorityExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodReason(zero, v.Id), s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// AssistanceDataForPagingExtIEsExtField is ProtocolExtensionField {{AssistanceDataForPaging-ExtIEs}} of TS 36.413: an extension field.
type AssistanceDataForPagingExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.AssistanceDataForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForPagingExtIEsExtField) WithoutReplay() AssistanceDataForPagingExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AssistanceDataForPagingExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AssistanceDataForPagingExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAssistanceDataForPagingExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAssistanceDataForPagingExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AssistanceDataForPagingExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceDataForPagingExtIEsExtField{}
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
	var zero s03.AssistanceDataForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAssistanceDataForPagingExtIEsValueMethodReason(zero, v.Id), s03.BridgeAssistanceDataForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeAssistanceDataForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// AssistanceDataForRecommendedCellsExtIEsExtField is ProtocolExtensionField {{AssistanceDataForRecommendedCells-ExtIEs}} of TS 36.413: an extension field.
type AssistanceDataForRecommendedCellsExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.AssistanceDataForRecommendedCellsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForRecommendedCellsExtIEsExtField) WithoutReplay() AssistanceDataForRecommendedCellsExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AssistanceDataForRecommendedCellsExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AssistanceDataForRecommendedCellsExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AssistanceDataForRecommendedCellsExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceDataForRecommendedCellsExtIEsExtField{}
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
	var zero s03.AssistanceDataForRecommendedCellsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodReason(zero, v.Id), s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BearersSubjectToEarlyStatusTransferItemExtIEsExtField is ProtocolExtensionField {{Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs}} of TS 36.413: an extension field.
type BearersSubjectToEarlyStatusTransferItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemExtIEsExtField) WithoutReplay() BearersSubjectToEarlyStatusTransferItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToEarlyStatusTransferItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToEarlyStatusTransferItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *BearersSubjectToEarlyStatusTransferItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToEarlyStatusTransferItemExtIEsExtField{}
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
	var zero s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BearersSubjectToDLDiscardingItemExtIEsExtField is ProtocolExtensionField {{Bearers-SubjectToDLDiscarding-ItemExtIEs}} of TS 36.413: an extension field.
type BearersSubjectToDLDiscardingItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.BearersSubjectToDLDiscardingItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemExtIEsExtField) WithoutReplay() BearersSubjectToDLDiscardingItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToDLDiscardingItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToDLDiscardingItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *BearersSubjectToDLDiscardingItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToDLDiscardingItemExtIEsExtField{}
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
	var zero s03.BearersSubjectToDLDiscardingItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BluetoothMeasurementConfigurationExtIEsExtField is ProtocolExtensionField {{BluetoothMeasurementConfiguration-ExtIEs}} of TS 36.413: an extension field.
type BluetoothMeasurementConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.BluetoothMeasurementConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BluetoothMeasurementConfigurationExtIEsExtField) WithoutReplay() BluetoothMeasurementConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BluetoothMeasurementConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BluetoothMeasurementConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *BluetoothMeasurementConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BluetoothMeasurementConfigurationExtIEsExtField{}
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
	var zero s03.BluetoothMeasurementConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodReason(zero, v.Id), s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CancelledCellinEAIItemExtIEsExtField is ProtocolExtensionField {{CancelledCellinEAI-Item-ExtIEs}} of TS 36.413: an extension field.
type CancelledCellinEAIItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CancelledCellinEAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinEAIItemExtIEsExtField) WithoutReplay() CancelledCellinEAIItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CancelledCellinEAIItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CancelledCellinEAIItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCancelledCellinEAIItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCancelledCellinEAIItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CancelledCellinEAIItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CancelledCellinEAIItemExtIEsExtField{}
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
	var zero s03.CancelledCellinEAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCancelledCellinEAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCancelledCellinEAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCancelledCellinEAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CancelledCellinTAIItemExtIEsExtField is ProtocolExtensionField {{CancelledCellinTAI-Item-ExtIEs}} of TS 36.413: an extension field.
type CancelledCellinTAIItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CancelledCellinTAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinTAIItemExtIEsExtField) WithoutReplay() CancelledCellinTAIItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CancelledCellinTAIItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CancelledCellinTAIItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCancelledCellinTAIItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCancelledCellinTAIItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CancelledCellinTAIItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CancelledCellinTAIItemExtIEsExtField{}
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
	var zero s03.CancelledCellinTAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCancelledCellinTAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCancelledCellinTAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCancelledCellinTAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellBasedMDTExtIEsExtField is ProtocolExtensionField {{CellBasedMDT-ExtIEs}} of TS 36.413: an extension field.
type CellBasedMDTExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CellBasedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedMDTExtIEsExtField) WithoutReplay() CellBasedMDTExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellBasedMDTExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellBasedMDTExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellBasedMDTExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellBasedMDTExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellBasedMDTExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedMDTExtIEsExtField{}
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
	var zero s03.CellBasedMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellBasedMDTExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellBasedMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCellBasedMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellBasedQMCExtIEsExtField is ProtocolExtensionField {{CellBasedQMC-ExtIEs}} of TS 36.413: an extension field.
type CellBasedQMCExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CellBasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedQMCExtIEsExtField) WithoutReplay() CellBasedQMCExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellBasedQMCExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellBasedQMCExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellBasedQMCExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellBasedQMCExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellBasedQMCExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedQMCExtIEsExtField{}
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
	var zero s03.CellBasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellBasedQMCExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellBasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCellBasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// Cdma2000OneXSRVCCInfoExtIEsExtField is ProtocolExtensionField {{Cdma2000OneXSRVCCInfo-ExtIEs}} of TS 36.413: an extension field.
type Cdma2000OneXSRVCCInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.Cdma2000OneXSRVCCInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v Cdma2000OneXSRVCCInfoExtIEsExtField) WithoutReplay() Cdma2000OneXSRVCCInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *Cdma2000OneXSRVCCInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *Cdma2000OneXSRVCCInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *Cdma2000OneXSRVCCInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cdma2000OneXSRVCCInfoExtIEsExtField{}
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
	var zero s03.Cdma2000OneXSRVCCInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CGIExtIEsExtField is ProtocolExtensionField {{CGI-ExtIEs}} of TS 36.413: an extension field.
type CGIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CGIExtIEsExtField) WithoutReplay() CGIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CGIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CGIExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCGIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCGIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CGIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CGIExtIEsExtField{}
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
	var zero s03.CGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCGIExtIEsValueMethodReason(zero, v.Id), s03.BridgeCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CNTypeRestrictionsItemExtIEsExtField is ProtocolExtensionField {{CNTypeRestrictions-Item-ExtIEs}} of TS 36.413: an extension field.
type CNTypeRestrictionsItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CNTypeRestrictionsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsItemExtIEsExtField) WithoutReplay() CNTypeRestrictionsItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CNTypeRestrictionsItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CNTypeRestrictionsItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CNTypeRestrictionsItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CNTypeRestrictionsItemExtIEsExtField{}
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
	var zero s03.CNTypeRestrictionsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CSGIdListItemExtIEsExtField is ProtocolExtensionField {{CSG-IdList-Item-ExtIEs}} of TS 36.413: an extension field.
type CSGIdListItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CSGIdListItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListItemExtIEsExtField) WithoutReplay() CSGIdListItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CSGIdListItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CSGIdListItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCSGIdListItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCSGIdListItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CSGIdListItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGIdListItemExtIEsExtField{}
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
	var zero s03.CSGIdListItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCSGIdListItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCSGIdListItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCSGIdListItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// COUNTvalueExtIEsExtField is ProtocolExtensionField {{COUNTvalue-ExtIEs}} of TS 36.413: an extension field.
type COUNTvalueExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.COUNTvalueExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvalueExtIEsExtField) WithoutReplay() COUNTvalueExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *COUNTvalueExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *COUNTvalueExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCOUNTvalueExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCOUNTvalueExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *COUNTvalueExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvalueExtIEsExtField{}
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
	var zero s03.COUNTvalueExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCOUNTvalueExtIEsValueMethodReason(zero, v.Id), s03.BridgeCOUNTvalueExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCOUNTvalueExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// COUNTValueExtendedExtIEsExtField is ProtocolExtensionField {{COUNTValueExtended-ExtIEs}} of TS 36.413: an extension field.
type COUNTValueExtendedExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.COUNTValueExtendedExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTValueExtendedExtIEsExtField) WithoutReplay() COUNTValueExtendedExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *COUNTValueExtendedExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *COUNTValueExtendedExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCOUNTValueExtendedExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCOUNTValueExtendedExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *COUNTValueExtendedExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTValueExtendedExtIEsExtField{}
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
	var zero s03.COUNTValueExtendedExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCOUNTValueExtendedExtIEsValueMethodReason(zero, v.Id), s03.BridgeCOUNTValueExtendedExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCOUNTValueExtendedExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// COUNTvaluePDCPSNlength18ExtIEsExtField is ProtocolExtensionField {{COUNTvaluePDCP-SNlength18-ExtIEs}} of TS 36.413: an extension field.
type COUNTvaluePDCPSNlength18ExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.COUNTvaluePDCPSNlength18ExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvaluePDCPSNlength18ExtIEsExtField) WithoutReplay() COUNTvaluePDCPSNlength18ExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *COUNTvaluePDCPSNlength18ExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *COUNTvaluePDCPSNlength18ExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *COUNTvaluePDCPSNlength18ExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvaluePDCPSNlength18ExtIEsExtField{}
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
	var zero s03.COUNTvaluePDCPSNlength18ExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodReason(zero, v.Id), s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CSGMembershipInfoExtIEsExtContainer is ProtocolExtensionContainer {{CSGMembershipInfo-ExtIEs}} of TS 36.413: a list of CSGMembershipInfoExtIEsExtField values.
type CSGMembershipInfoExtIEsExtContainer []CSGMembershipInfoExtIEsExtField

// CSGMembershipInfoExtIEsExtField is ProtocolExtensionField {{CSGMembershipInfo-ExtIEs}} of TS 36.413: an extension field.
type CSGMembershipInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s03.CSGMembershipInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGMembershipInfoExtIEsExtField) WithoutReplay() CSGMembershipInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CSGMembershipInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CSGMembershipInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCSGMembershipInfoExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCSGMembershipInfoExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CSGMembershipInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGMembershipInfoExtIEsExtField{}
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
	var zero s03.CSGMembershipInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCSGMembershipInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeCSGMembershipInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s03.BridgeCSGMembershipInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// additionalGUTIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AdditionalGUTIExtIEsValue].
type AdditionalGUTIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.AdditionalGUTIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.AdditionalGUTIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// allocationAndRetentionPriorityExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AllocationAndRetentionPriorityExtIEsValue].
type AllocationAndRetentionPriorityExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.AllocationAndRetentionPriorityExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.AllocationAndRetentionPriorityExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// informationForCECapableUEsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InformationForCECapableUEsExtIEsValue].
type InformationForCECapableUEsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.InformationForCECapableUEsExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.InformationForCECapableUEsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// assistanceDataForPagingExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceDataForPagingExtIEsValue].
type AssistanceDataForPagingExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.AssistanceDataForPagingExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.AssistanceDataForPagingExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// assistanceDataForRecommendedCellsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceDataForRecommendedCellsExtIEsValue].
type AssistanceDataForRecommendedCellsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.AssistanceDataForRecommendedCellsExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.AssistanceDataForRecommendedCellsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// bearersSubjectToDLDiscardingItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToDLDiscardingItemExtIEsValue].
type BearersSubjectToDLDiscardingItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.BearersSubjectToDLDiscardingItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.BearersSubjectToDLDiscardingItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// bearersSubjectToEarlyStatusTransferItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToEarlyStatusTransferItemExtIEsValue].
type BearersSubjectToEarlyStatusTransferItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// bluetoothMeasurementConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[BluetoothMeasurementConfigurationExtIEsValue].
type BluetoothMeasurementConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.BluetoothMeasurementConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.BluetoothMeasurementConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CGIExtIEsValue].
type CGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CGIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cNTypeRestrictionsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CNTypeRestrictionsItemExtIEsValue].
type CNTypeRestrictionsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CNTypeRestrictionsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CNTypeRestrictionsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cOUNTValueExtendedExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[COUNTValueExtendedExtIEsValue].
type COUNTValueExtendedExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.COUNTValueExtendedExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.COUNTValueExtendedExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cOUNTvalueExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[COUNTvalueExtIEsValue].
type COUNTvalueExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.COUNTvalueExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.COUNTvalueExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cOUNTvaluePDCPSNlength18ExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[COUNTvaluePDCPSNlength18ExtIEsValue].
type COUNTvaluePDCPSNlength18ExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.COUNTvaluePDCPSNlength18ExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.COUNTvaluePDCPSNlength18ExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cSGIdListItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CSGIdListItemExtIEsValue].
type CSGIdListItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CSGIdListItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CSGIdListItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cSGMembershipInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CSGMembershipInfoExtIEsValue].
type CSGMembershipInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CSGMembershipInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CSGMembershipInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cancelledCellinEAIItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CancelledCellinEAIItemExtIEsValue].
type CancelledCellinEAIItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CancelledCellinEAIItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CancelledCellinEAIItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cancelledCellinTAIItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CancelledCellinTAIItemExtIEsValue].
type CancelledCellinTAIItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CancelledCellinTAIItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CancelledCellinTAIItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cdma2000OneXSRVCCInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[Cdma2000OneXSRVCCInfoExtIEsValue].
type Cdma2000OneXSRVCCInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.Cdma2000OneXSRVCCInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.Cdma2000OneXSRVCCInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cellBasedMDTExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CellBasedMDTExtIEsValue].
type CellBasedMDTExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CellBasedMDTExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CellBasedMDTExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cellBasedQMCExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CellBasedQMCExtIEsValue].
type CellBasedQMCExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CellBasedQMCExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CellBasedQMCExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cellIDBroadcastItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CellIDBroadcastItemExtIEsValue].
type CellIDBroadcastItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CellIDBroadcastItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CellIDBroadcastItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cellIDCancelledItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CellIDCancelledItemExtIEsValue].
type CellIDCancelledItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CellIDCancelledItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CellIDCancelledItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cellIdentifierAndCELevelForCECapableUEsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CellIdentifierAndCELevelForCECapableUEsExtIEsValue].
type CellIdentifierAndCELevelForCECapableUEsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// cellTypeExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CellTypeExtIEsValue].
type CellTypeExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CellTypeExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CellTypeExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// completedCellinEAIItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CompletedCellinEAIItemExtIEsValue].
type CompletedCellinEAIItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CompletedCellinEAIItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CompletedCellinEAIItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// completedCellinTAIItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CompletedCellinTAIItemExtIEsValue].
type CompletedCellinTAIItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CompletedCellinTAIItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CompletedCellinTAIItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// connectedengNBItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ConnectedengNBItemExtIEsValue].
type ConnectedengNBItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.ConnectedengNBItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.ConnectedengNBItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// contextatSourceExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ContextatSourceExtIEsValue].
type ContextatSourceExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.ContextatSourceExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.ContextatSourceExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// criticalityDiagnosticsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CriticalityDiagnosticsExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CriticalityDiagnosticsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// criticalityDiagnosticsIEItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[CriticalityDiagnosticsIEItemExtIEsValue].
type CriticalityDiagnosticsIEItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.CriticalityDiagnosticsIEItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.CriticalityDiagnosticsIEItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// dAPSRequestInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[DAPSRequestInfoExtIEsValue].
type DAPSRequestInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.DAPSRequestInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.DAPSRequestInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// dAPSResponseInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[DAPSResponseInfoExtIEsValue].
type DAPSResponseInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.DAPSResponseInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.DAPSResponseInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// dAPSResponseInfoItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[DAPSResponseInfoItemExtIEsValue].
type DAPSResponseInfoItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.DAPSResponseInfoItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.DAPSResponseInfoItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// dLCPSecurityInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[DLCPSecurityInformationExtIEsValue].
type DLCPSecurityInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.DLCPSecurityInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.DLCPSecurityInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eNBStatusTransferTransparentContainerExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENBStatusTransferTransparentContainerExtIEsValue].
type ENBStatusTransferTransparentContainerExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ENBStatusTransferTransparentContainerExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ENBStatusTransferTransparentContainerExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eNBX2ExtTLAExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENBX2ExtTLAExtIEsValue].
type ENBX2ExtTLAExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ENBX2ExtTLAExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ENBX2ExtTLAExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eNDCSONConfigurationTransferExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENDCSONConfigurationTransferExtIEsValue].
type ENDCSONConfigurationTransferExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ENDCSONConfigurationTransferExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ENDCSONConfigurationTransferExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eNDCSONeNBIdentificationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENDCSONeNBIdentificationExtIEsValue].
type ENDCSONeNBIdentificationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ENDCSONeNBIdentificationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ENDCSONeNBIdentificationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eNDCSONengNBIdentificationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENDCSONengNBIdentificationExtIEsValue].
type ENDCSONengNBIdentificationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ENDCSONengNBIdentificationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ENDCSONengNBIdentificationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eNDCTransferTypeReplyExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENDCTransferTypeReplyExtIEsValue].
type ENDCTransferTypeReplyExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ENDCTransferTypeReplyExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ENDCTransferTypeReplyExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eNDCTransferTypeRequestExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENDCTransferTypeRequestExtIEsValue].
type ENDCTransferTypeRequestExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ENDCTransferTypeRequestExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ENDCTransferTypeRequestExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABAdmittedItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABAdmittedItemExtIEsValue].
type ERABAdmittedItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABAdmittedItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABAdmittedItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABDataForwardingItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABDataForwardingItemExtIEsValue].
type ERABDataForwardingItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABDataForwardingItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABDataForwardingItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABFailedToResumeItemResumeReqExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedToResumeItemResumeReqExtIEsValue].
type ERABFailedToResumeItemResumeReqExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABFailedToResumeItemResumeReqExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABFailedToResumeItemResumeReqExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABFailedToResumeItemResumeResExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedToResumeItemResumeResExtIEsValue].
type ERABFailedToResumeItemResumeResExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABFailedToResumeItemResumeResExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABFailedToResumeItemResumeResExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABFailedToSetupItemHOReqAckExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABFailedToSetupItemHOReqAckExtIEsValue].
type ERABFailedToSetupItemHOReqAckExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABFailedToSetupItemHOReqAckExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABFailedToSetupItemHOReqAckExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABItemExtIEsValue].
type ERABItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABModifyItemBearerModConfExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyItemBearerModConfExtIEsValue].
type ERABModifyItemBearerModConfExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABModifyItemBearerModConfExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABModifyItemBearerModConfExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABModifyItemBearerModResExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyItemBearerModResExtIEsValue].
type ERABModifyItemBearerModResExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABModifyItemBearerModResExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABModifyItemBearerModResExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABNotToBeModifiedItemBearerModIndExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABNotToBeModifiedItemBearerModIndExtIEsValue].
type ERABNotToBeModifiedItemBearerModIndExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABReleaseItemBearerRelCompExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABReleaseItemBearerRelCompExtIEsValue].
type ERABReleaseItemBearerRelCompExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABReleaseItemBearerRelCompExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABReleaseItemBearerRelCompExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABSecurityResultItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABSecurityResultItemExtIEsValue].
type ERABSecurityResultItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABSecurityResultItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABSecurityResultItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABSetupItemBearerSUResExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupItemBearerSUResExtIEsValue].
type ERABSetupItemBearerSUResExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABSetupItemBearerSUResExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABSetupItemBearerSUResExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABSetupItemCtxtSUResExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupItemCtxtSUResExtIEsValue].
type ERABSetupItemCtxtSUResExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABSetupItemCtxtSUResExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABSetupItemCtxtSUResExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABToBeModifiedItemBearerModIndExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeModifiedItemBearerModIndExtIEsValue].
type ERABToBeModifiedItemBearerModIndExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABToBeModifiedItemBearerModIndExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABToBeModifiedItemBearerModIndExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABToBeSwitchedULItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeSwitchedULItemExtIEsValue].
type ERABToBeSwitchedULItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABToBeSwitchedULItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABToBeSwitchedULItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABToBeUpdatedItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABToBeUpdatedItemExtIEsValue].
type ERABToBeUpdatedItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABToBeUpdatedItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABToBeUpdatedItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABUsageReportItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABUsageReportItemExtIEsValue].
type ERABUsageReportItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ERABUsageReportItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ERABUsageReportItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eUTRANCGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[EUTRANCGIExtIEsValue].
type EUTRANCGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.EUTRANCGIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.EUTRANCGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// emergencyAreaIDBroadcastItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[EmergencyAreaIDBroadcastItemExtIEsValue].
type EmergencyAreaIDBroadcastItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.EmergencyAreaIDBroadcastItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.EmergencyAreaIDBroadcastItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// emergencyAreaIDCancelledItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[EmergencyAreaIDCancelledItemExtIEsValue].
type EmergencyAreaIDCancelledItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.EmergencyAreaIDCancelledItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.EmergencyAreaIDCancelledItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eventL1LoggedMDTConfigExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[EventL1LoggedMDTConfigExtIEsValue].
type EventL1LoggedMDTConfigExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.EventL1LoggedMDTConfigExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.EventL1LoggedMDTConfigExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eventTriggerExtIEValueProtocolOpenValue is the concrete protocolOpenValue[EventTriggerExtIEValue].
type EventTriggerExtIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.EventTriggerExtIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.EventTriggerExtIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// expectedUEActivityBehaviourExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ExpectedUEActivityBehaviourExtIEsValue].
type ExpectedUEActivityBehaviourExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.ExpectedUEActivityBehaviourExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.ExpectedUEActivityBehaviourExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// expectedUEBehaviourExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ExpectedUEBehaviourExtIEsValue].
type ExpectedUEBehaviourExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.ExpectedUEBehaviourExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.ExpectedUEBehaviourExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// fiveGSTAIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[FiveGSTAIExtIEsValue].
type FiveGSTAIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.FiveGSTAIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.FiveGSTAIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// forbiddenLAsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ForbiddenLAsItemExtIEsValue].
type ForbiddenLAsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.ForbiddenLAsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.ForbiddenLAsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// forbiddenTAsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ForbiddenTAsItemExtIEsValue].
type ForbiddenTAsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.ForbiddenTAsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.ForbiddenTAsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// gBRQosInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[GBRQosInformationExtIEsValue].
type GBRQosInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.GBRQosInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.GBRQosInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// gERANCellIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[GERANCellIDExtIEsValue].
type GERANCellIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.GERANCellIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.GERANCellIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// gNBExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[GNBExtIEsValue].
type GNBExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.GNBExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.GNBExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// gUMMEIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[GUMMEIExtIEsValue].
type GUMMEIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.GUMMEIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.GUMMEIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// globalENBIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[GlobalENBIDExtIEsValue].
type GlobalENBIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.GlobalENBIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.GlobalENBIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// globalEnGNBIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[GlobalEnGNBIDExtIEsValue].
type GlobalEnGNBIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.GlobalEnGNBIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.GlobalEnGNBIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// globalGNBIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[GlobalGNBIDExtIEsValue].
type GlobalGNBIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.GlobalGNBIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.GlobalGNBIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// informationOnRecommendedCellsAndENBsForPagingExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InformationOnRecommendedCellsAndENBsForPagingExtIEsValue].
type InformationOnRecommendedCellsAndENBsForPagingExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// AdditionalGUTIExtIEsIEField uses the ProtocolIE-Field shape for object set Additional-GUTI-ExtIEs of TS 36.413.
type AdditionalGUTIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.AdditionalGUTIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AdditionalGUTIExtIEsIEField) WithoutReplay() AdditionalGUTIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AdditionalGUTIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AdditionalGUTIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAdditionalGUTIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAdditionalGUTIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AdditionalGUTIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AdditionalGUTIExtIEsIEField{}
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
	var zero s03.AdditionalGUTIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAdditionalGUTIExtIEsValueMethodReason(zero, v.Id), s03.BridgeAdditionalGUTIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeAdditionalGUTIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// AdditionalGUTIExtIEsIEContainer uses the ProtocolIE-Container shape for object set Additional-GUTI-ExtIEs of TS 36.413: a list of AdditionalGUTIExtIEsIEField values.
type AdditionalGUTIExtIEsIEContainer []AdditionalGUTIExtIEsIEField

// AllocationAndRetentionPriorityExtIEsIEField uses the ProtocolIE-Field shape for object set AllocationAndRetentionPriority-ExtIEs of TS 36.413.
type AllocationAndRetentionPriorityExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.AllocationAndRetentionPriorityExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AllocationAndRetentionPriorityExtIEsIEField) WithoutReplay() AllocationAndRetentionPriorityExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AllocationAndRetentionPriorityExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AllocationAndRetentionPriorityExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AllocationAndRetentionPriorityExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AllocationAndRetentionPriorityExtIEsIEField{}
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
	var zero s03.AllocationAndRetentionPriorityExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodReason(zero, v.Id), s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// AllocationAndRetentionPriorityExtIEsIEContainer uses the ProtocolIE-Container shape for object set AllocationAndRetentionPriority-ExtIEs of TS 36.413: a list of AllocationAndRetentionPriorityExtIEsIEField values.
type AllocationAndRetentionPriorityExtIEsIEContainer []AllocationAndRetentionPriorityExtIEsIEField

// AssistanceDataForPagingExtIEsIEField uses the ProtocolIE-Field shape for object set AssistanceDataForPaging-ExtIEs of TS 36.413.
type AssistanceDataForPagingExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.AssistanceDataForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForPagingExtIEsIEField) WithoutReplay() AssistanceDataForPagingExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AssistanceDataForPagingExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AssistanceDataForPagingExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAssistanceDataForPagingExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAssistanceDataForPagingExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AssistanceDataForPagingExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceDataForPagingExtIEsIEField{}
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
	var zero s03.AssistanceDataForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAssistanceDataForPagingExtIEsValueMethodReason(zero, v.Id), s03.BridgeAssistanceDataForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeAssistanceDataForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// AssistanceDataForPagingExtIEsIEContainer uses the ProtocolIE-Container shape for object set AssistanceDataForPaging-ExtIEs of TS 36.413: a list of AssistanceDataForPagingExtIEsIEField values.
type AssistanceDataForPagingExtIEsIEContainer []AssistanceDataForPagingExtIEsIEField

// AssistanceDataForRecommendedCellsExtIEsIEField uses the ProtocolIE-Field shape for object set AssistanceDataForRecommendedCells-ExtIEs of TS 36.413.
type AssistanceDataForRecommendedCellsExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.AssistanceDataForRecommendedCellsExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForRecommendedCellsExtIEsIEField) WithoutReplay() AssistanceDataForRecommendedCellsExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *AssistanceDataForRecommendedCellsExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *AssistanceDataForRecommendedCellsExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *AssistanceDataForRecommendedCellsExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceDataForRecommendedCellsExtIEsIEField{}
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
	var zero s03.AssistanceDataForRecommendedCellsExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodReason(zero, v.Id), s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// AssistanceDataForRecommendedCellsExtIEsIEContainer uses the ProtocolIE-Container shape for object set AssistanceDataForRecommendedCells-ExtIEs of TS 36.413: a list of AssistanceDataForRecommendedCellsExtIEsIEField values.
type AssistanceDataForRecommendedCellsExtIEsIEContainer []AssistanceDataForRecommendedCellsExtIEsIEField

// BearersSubjectToDLDiscardingItemExtIEsIEField uses the ProtocolIE-Field shape for object set Bearers-SubjectToDLDiscarding-ItemExtIEs of TS 36.413.
type BearersSubjectToDLDiscardingItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.BearersSubjectToDLDiscardingItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemExtIEsIEField) WithoutReplay() BearersSubjectToDLDiscardingItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToDLDiscardingItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToDLDiscardingItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *BearersSubjectToDLDiscardingItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToDLDiscardingItemExtIEsIEField{}
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
	var zero s03.BearersSubjectToDLDiscardingItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BearersSubjectToDLDiscardingItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set Bearers-SubjectToDLDiscarding-ItemExtIEs of TS 36.413: a list of BearersSubjectToDLDiscardingItemExtIEsIEField values.
type BearersSubjectToDLDiscardingItemExtIEsIEContainer []BearersSubjectToDLDiscardingItemExtIEsIEField

// BearersSubjectToEarlyStatusTransferItemExtIEsIEField uses the ProtocolIE-Field shape for object set Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs of TS 36.413.
type BearersSubjectToEarlyStatusTransferItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemExtIEsIEField) WithoutReplay() BearersSubjectToEarlyStatusTransferItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToEarlyStatusTransferItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToEarlyStatusTransferItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *BearersSubjectToEarlyStatusTransferItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToEarlyStatusTransferItemExtIEsIEField{}
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
	var zero s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BearersSubjectToEarlyStatusTransferItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs of TS 36.413: a list of BearersSubjectToEarlyStatusTransferItemExtIEsIEField values.
type BearersSubjectToEarlyStatusTransferItemExtIEsIEContainer []BearersSubjectToEarlyStatusTransferItemExtIEsIEField

// BluetoothMeasurementConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set BluetoothMeasurementConfiguration-ExtIEs of TS 36.413.
type BluetoothMeasurementConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.BluetoothMeasurementConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BluetoothMeasurementConfigurationExtIEsIEField) WithoutReplay() BluetoothMeasurementConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BluetoothMeasurementConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BluetoothMeasurementConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *BluetoothMeasurementConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BluetoothMeasurementConfigurationExtIEsIEField{}
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
	var zero s03.BluetoothMeasurementConfigurationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodReason(zero, v.Id), s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BluetoothMeasurementConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set BluetoothMeasurementConfiguration-ExtIEs of TS 36.413: a list of BluetoothMeasurementConfigurationExtIEsIEField values.
type BluetoothMeasurementConfigurationExtIEsIEContainer []BluetoothMeasurementConfigurationExtIEsIEField

// CGIExtIEsIEField uses the ProtocolIE-Field shape for object set CGI-ExtIEs of TS 36.413.
type CGIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CGIExtIEsIEField) WithoutReplay() CGIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CGIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CGIExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCGIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCGIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CGIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CGIExtIEsIEField{}
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
	var zero s03.CGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCGIExtIEsValueMethodReason(zero, v.Id), s03.BridgeCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CGIExtIEsIEContainer uses the ProtocolIE-Container shape for object set CGI-ExtIEs of TS 36.413: a list of CGIExtIEsIEField values.
type CGIExtIEsIEContainer []CGIExtIEsIEField

// CNTypeRestrictionsItemExtIEsIEField uses the ProtocolIE-Field shape for object set CNTypeRestrictions-Item-ExtIEs of TS 36.413.
type CNTypeRestrictionsItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CNTypeRestrictionsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsItemExtIEsIEField) WithoutReplay() CNTypeRestrictionsItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CNTypeRestrictionsItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CNTypeRestrictionsItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CNTypeRestrictionsItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CNTypeRestrictionsItemExtIEsIEField{}
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
	var zero s03.CNTypeRestrictionsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CNTypeRestrictionsItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CNTypeRestrictions-Item-ExtIEs of TS 36.413: a list of CNTypeRestrictionsItemExtIEsIEField values.
type CNTypeRestrictionsItemExtIEsIEContainer []CNTypeRestrictionsItemExtIEsIEField

// COUNTValueExtendedExtIEsIEField uses the ProtocolIE-Field shape for object set COUNTValueExtended-ExtIEs of TS 36.413.
type COUNTValueExtendedExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.COUNTValueExtendedExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTValueExtendedExtIEsIEField) WithoutReplay() COUNTValueExtendedExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *COUNTValueExtendedExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *COUNTValueExtendedExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCOUNTValueExtendedExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCOUNTValueExtendedExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *COUNTValueExtendedExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTValueExtendedExtIEsIEField{}
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
	var zero s03.COUNTValueExtendedExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCOUNTValueExtendedExtIEsValueMethodReason(zero, v.Id), s03.BridgeCOUNTValueExtendedExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCOUNTValueExtendedExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// COUNTValueExtendedExtIEsIEContainer uses the ProtocolIE-Container shape for object set COUNTValueExtended-ExtIEs of TS 36.413: a list of COUNTValueExtendedExtIEsIEField values.
type COUNTValueExtendedExtIEsIEContainer []COUNTValueExtendedExtIEsIEField

// COUNTvalueExtIEsIEField uses the ProtocolIE-Field shape for object set COUNTvalue-ExtIEs of TS 36.413.
type COUNTvalueExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.COUNTvalueExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvalueExtIEsIEField) WithoutReplay() COUNTvalueExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *COUNTvalueExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *COUNTvalueExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCOUNTvalueExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCOUNTvalueExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *COUNTvalueExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvalueExtIEsIEField{}
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
	var zero s03.COUNTvalueExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCOUNTvalueExtIEsValueMethodReason(zero, v.Id), s03.BridgeCOUNTvalueExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCOUNTvalueExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// COUNTvalueExtIEsIEContainer uses the ProtocolIE-Container shape for object set COUNTvalue-ExtIEs of TS 36.413: a list of COUNTvalueExtIEsIEField values.
type COUNTvalueExtIEsIEContainer []COUNTvalueExtIEsIEField

// COUNTvaluePDCPSNlength18ExtIEsIEField uses the ProtocolIE-Field shape for object set COUNTvaluePDCP-SNlength18-ExtIEs of TS 36.413.
type COUNTvaluePDCPSNlength18ExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.COUNTvaluePDCPSNlength18ExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvaluePDCPSNlength18ExtIEsIEField) WithoutReplay() COUNTvaluePDCPSNlength18ExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *COUNTvaluePDCPSNlength18ExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *COUNTvaluePDCPSNlength18ExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *COUNTvaluePDCPSNlength18ExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvaluePDCPSNlength18ExtIEsIEField{}
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
	var zero s03.COUNTvaluePDCPSNlength18ExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodReason(zero, v.Id), s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// COUNTvaluePDCPSNlength18ExtIEsIEContainer uses the ProtocolIE-Container shape for object set COUNTvaluePDCP-SNlength18-ExtIEs of TS 36.413: a list of COUNTvaluePDCPSNlength18ExtIEsIEField values.
type COUNTvaluePDCPSNlength18ExtIEsIEContainer []COUNTvaluePDCPSNlength18ExtIEsIEField

// CSGIdListItemExtIEsIEField uses the ProtocolIE-Field shape for object set CSG-IdList-Item-ExtIEs of TS 36.413.
type CSGIdListItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CSGIdListItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListItemExtIEsIEField) WithoutReplay() CSGIdListItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CSGIdListItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CSGIdListItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCSGIdListItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCSGIdListItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CSGIdListItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGIdListItemExtIEsIEField{}
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
	var zero s03.CSGIdListItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCSGIdListItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCSGIdListItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCSGIdListItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CSGIdListItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CSG-IdList-Item-ExtIEs of TS 36.413: a list of CSGIdListItemExtIEsIEField values.
type CSGIdListItemExtIEsIEContainer []CSGIdListItemExtIEsIEField

// CSGMembershipInfoExtIEsIEField uses the ProtocolIE-Field shape for object set CSGMembershipInfo-ExtIEs of TS 36.413.
type CSGMembershipInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CSGMembershipInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGMembershipInfoExtIEsIEField) WithoutReplay() CSGMembershipInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CSGMembershipInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CSGMembershipInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCSGMembershipInfoExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCSGMembershipInfoExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CSGMembershipInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGMembershipInfoExtIEsIEField{}
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
	var zero s03.CSGMembershipInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCSGMembershipInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeCSGMembershipInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCSGMembershipInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CSGMembershipInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set CSGMembershipInfo-ExtIEs of TS 36.413: a list of CSGMembershipInfoExtIEsIEField values.
type CSGMembershipInfoExtIEsIEContainer []CSGMembershipInfoExtIEsIEField

// CancelledCellinEAIItemExtIEsIEField uses the ProtocolIE-Field shape for object set CancelledCellinEAI-Item-ExtIEs of TS 36.413.
type CancelledCellinEAIItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CancelledCellinEAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinEAIItemExtIEsIEField) WithoutReplay() CancelledCellinEAIItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CancelledCellinEAIItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CancelledCellinEAIItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCancelledCellinEAIItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCancelledCellinEAIItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CancelledCellinEAIItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CancelledCellinEAIItemExtIEsIEField{}
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
	var zero s03.CancelledCellinEAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCancelledCellinEAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCancelledCellinEAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCancelledCellinEAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CancelledCellinEAIItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CancelledCellinEAI-Item-ExtIEs of TS 36.413: a list of CancelledCellinEAIItemExtIEsIEField values.
type CancelledCellinEAIItemExtIEsIEContainer []CancelledCellinEAIItemExtIEsIEField

// CancelledCellinTAIItemExtIEsIEField uses the ProtocolIE-Field shape for object set CancelledCellinTAI-Item-ExtIEs of TS 36.413.
type CancelledCellinTAIItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CancelledCellinTAIItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinTAIItemExtIEsIEField) WithoutReplay() CancelledCellinTAIItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CancelledCellinTAIItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CancelledCellinTAIItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCancelledCellinTAIItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCancelledCellinTAIItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CancelledCellinTAIItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CancelledCellinTAIItemExtIEsIEField{}
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
	var zero s03.CancelledCellinTAIItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCancelledCellinTAIItemExtIEsValueMethodReason(zero, v.Id), s03.BridgeCancelledCellinTAIItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCancelledCellinTAIItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CancelledCellinTAIItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set CancelledCellinTAI-Item-ExtIEs of TS 36.413: a list of CancelledCellinTAIItemExtIEsIEField values.
type CancelledCellinTAIItemExtIEsIEContainer []CancelledCellinTAIItemExtIEsIEField

// Cdma2000OneXSRVCCInfoExtIEsIEField uses the ProtocolIE-Field shape for object set Cdma2000OneXSRVCCInfo-ExtIEs of TS 36.413.
type Cdma2000OneXSRVCCInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.Cdma2000OneXSRVCCInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v Cdma2000OneXSRVCCInfoExtIEsIEField) WithoutReplay() Cdma2000OneXSRVCCInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *Cdma2000OneXSRVCCInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *Cdma2000OneXSRVCCInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *Cdma2000OneXSRVCCInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cdma2000OneXSRVCCInfoExtIEsIEField{}
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
	var zero s03.Cdma2000OneXSRVCCInfoExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodReason(zero, v.Id), s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// Cdma2000OneXSRVCCInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set Cdma2000OneXSRVCCInfo-ExtIEs of TS 36.413: a list of Cdma2000OneXSRVCCInfoExtIEsIEField values.
type Cdma2000OneXSRVCCInfoExtIEsIEContainer []Cdma2000OneXSRVCCInfoExtIEsIEField

// CellBasedMDTExtIEsIEField uses the ProtocolIE-Field shape for object set CellBasedMDT-ExtIEs of TS 36.413.
type CellBasedMDTExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s03.CellBasedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedMDTExtIEsIEField) WithoutReplay() CellBasedMDTExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellBasedMDTExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellBasedMDTExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if !s03.BridgeCellBasedMDTExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), BridgeInt64Ptr(0), BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s03.BridgeCellBasedMDTExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *CellBasedMDTExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedMDTExtIEsIEField{}
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
	var zero s03.CellBasedMDTExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s03.BridgeCellBasedMDTExtIEsValueMethodReason(zero, v.Id), s03.BridgeCellBasedMDTExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s03.BridgeCellBasedMDTExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// CellBasedMDTExtIEsIEContainer uses the ProtocolIE-Container shape for object set CellBasedMDT-ExtIEs of TS 36.413: a list of CellBasedMDTExtIEsIEField values.
type CellBasedMDTExtIEsIEContainer []CellBasedMDTExtIEsIEField

// AdditionalGUTIExtIEsExtFieldValueCodec is the concrete ValueCodec[AdditionalGUTIExtIEsExtField].
type AdditionalGUTIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AdditionalGUTIExtIEsExtField, error)
	encode  func(AdditionalGUTIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AdditionalGUTIExtIEsExtField, aper.DecodeState) (AdditionalGUTIExtIEsExtField, aper.Snapshot)
	compare func(AdditionalGUTIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AdditionalGUTIExtIEsExtFieldValueCodec) New(value AdditionalGUTIExtIEsExtField) (AdditionalGUTIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return AdditionalGUTIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AdditionalGUTIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AdditionalGUTIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AdditionalGUTIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AdditionalGUTIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AdditionalGUTIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AdditionalGUTIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AdditionalGUTIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AdditionalGUTIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AdditionalGUTIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AdditionalGUTIExtIEsExtFieldValueCodec) EncodeAPER(value AdditionalGUTIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AdditionalGUTIExtIEsExtFieldValueCodec) encodeBudgetValue(value AdditionalGUTIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AdditionalGUTIExtIEsExtFieldValueCodec) encodeChanged(value AdditionalGUTIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AllocationAndRetentionPriorityExtIEsExtFieldValueCodec is the concrete ValueCodec[AllocationAndRetentionPriorityExtIEsExtField].
type AllocationAndRetentionPriorityExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtField, error)
	encode  func(AllocationAndRetentionPriorityExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AllocationAndRetentionPriorityExtIEsExtField, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtField, aper.Snapshot)
	compare func(AllocationAndRetentionPriorityExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) New(value AllocationAndRetentionPriorityExtIEsExtField) (AllocationAndRetentionPriorityExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AllocationAndRetentionPriorityExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AllocationAndRetentionPriorityExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) EncodeAPER(value AllocationAndRetentionPriorityExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) encodeBudgetValue(value AllocationAndRetentionPriorityExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) encodeChanged(value AllocationAndRetentionPriorityExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AssistanceDataForPagingExtIEsExtFieldValueCodec is the concrete ValueCodec[AssistanceDataForPagingExtIEsExtField].
type AssistanceDataForPagingExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AssistanceDataForPagingExtIEsExtField, error)
	encode  func(AssistanceDataForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AssistanceDataForPagingExtIEsExtField, aper.DecodeState) (AssistanceDataForPagingExtIEsExtField, aper.Snapshot)
	compare func(AssistanceDataForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AssistanceDataForPagingExtIEsExtFieldValueCodec) New(value AssistanceDataForPagingExtIEsExtField) (AssistanceDataForPagingExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return AssistanceDataForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceDataForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceDataForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AssistanceDataForPagingExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AssistanceDataForPagingExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceDataForPagingExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AssistanceDataForPagingExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AssistanceDataForPagingExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AssistanceDataForPagingExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AssistanceDataForPagingExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AssistanceDataForPagingExtIEsExtFieldValueCodec) EncodeAPER(value AssistanceDataForPagingExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AssistanceDataForPagingExtIEsExtFieldValueCodec) encodeBudgetValue(value AssistanceDataForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AssistanceDataForPagingExtIEsExtFieldValueCodec) encodeChanged(value AssistanceDataForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec is the concrete ValueCodec[AssistanceDataForRecommendedCellsExtIEsExtField].
type AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtField, error)
	encode  func(AssistanceDataForRecommendedCellsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AssistanceDataForRecommendedCellsExtIEsExtField, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtField, aper.Snapshot)
	compare func(AssistanceDataForRecommendedCellsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) New(value AssistanceDataForRecommendedCellsExtIEsExtField) (AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) EncodeAPER(value AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) encodeBudgetValue(value AssistanceDataForRecommendedCellsExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) encodeChanged(value AssistanceDataForRecommendedCellsExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItemExtIEsExtField].
type BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtField, error)
	encode  func(BearersSubjectToDLDiscardingItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItemExtIEsExtField, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtField, aper.Snapshot)
	compare func(BearersSubjectToDLDiscardingItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) New(value BearersSubjectToDLDiscardingItemExtIEsExtField) (BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItemExtIEsExtField].
type BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtField, error)
	encode  func(BearersSubjectToEarlyStatusTransferItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItemExtIEsExtField, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtField, aper.Snapshot)
	compare func(BearersSubjectToEarlyStatusTransferItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) New(value BearersSubjectToEarlyStatusTransferItemExtIEsExtField) (BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[BluetoothMeasurementConfigurationExtIEsExtField].
type BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtField, error)
	encode  func(BluetoothMeasurementConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BluetoothMeasurementConfigurationExtIEsExtField, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtField, aper.Snapshot)
	compare func(BluetoothMeasurementConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) New(value BluetoothMeasurementConfigurationExtIEsExtField) (BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value BluetoothMeasurementConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) encodeChanged(value BluetoothMeasurementConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CGIExtIEsExtFieldValueCodec is the concrete ValueCodec[CGIExtIEsExtField].
type CGIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CGIExtIEsExtField, error)
	encode  func(CGIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CGIExtIEsExtField, aper.DecodeState) (CGIExtIEsExtField, aper.Snapshot)
	compare func(CGIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CGIExtIEsExtFieldValueCodec) New(value CGIExtIEsExtField) (CGIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CGIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CGIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CGIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CGIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CGIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CGIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CGIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CGIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CGIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CGIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CGIExtIEsExtFieldValueCodec) EncodeAPER(value CGIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CGIExtIEsExtFieldValueCodec) encodeBudgetValue(value CGIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CGIExtIEsExtFieldValueCodec) encodeChanged(value CGIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CNTypeRestrictionsItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CNTypeRestrictionsItemExtIEsExtField].
type CNTypeRestrictionsItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtField, error)
	encode  func(CNTypeRestrictionsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CNTypeRestrictionsItemExtIEsExtField, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtField, aper.Snapshot)
	compare func(CNTypeRestrictionsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CNTypeRestrictionsItemExtIEsExtFieldValueCodec) New(value CNTypeRestrictionsItemExtIEsExtField) (CNTypeRestrictionsItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CNTypeRestrictionsItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CNTypeRestrictionsItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CNTypeRestrictionsItemExtIEsExtFieldValueCodec) EncodeAPER(value CNTypeRestrictionsItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CNTypeRestrictionsItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CNTypeRestrictionsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CNTypeRestrictionsItemExtIEsExtFieldValueCodec) encodeChanged(value CNTypeRestrictionsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTValueExtendedExtIEsExtFieldValueCodec is the concrete ValueCodec[COUNTValueExtendedExtIEsExtField].
type COUNTValueExtendedExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTValueExtendedExtIEsExtField, error)
	encode  func(COUNTValueExtendedExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTValueExtendedExtIEsExtField, aper.DecodeState) (COUNTValueExtendedExtIEsExtField, aper.Snapshot)
	compare func(COUNTValueExtendedExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTValueExtendedExtIEsExtFieldValueCodec) New(value COUNTValueExtendedExtIEsExtField) (COUNTValueExtendedExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return COUNTValueExtendedExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTValueExtendedExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTValueExtendedExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTValueExtendedExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTValueExtendedExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTValueExtendedExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTValueExtendedExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTValueExtendedExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTValueExtendedExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTValueExtendedExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTValueExtendedExtIEsExtFieldValueCodec) EncodeAPER(value COUNTValueExtendedExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c COUNTValueExtendedExtIEsExtFieldValueCodec) encodeBudgetValue(value COUNTValueExtendedExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTValueExtendedExtIEsExtFieldValueCodec) encodeChanged(value COUNTValueExtendedExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTvalueExtIEsExtFieldValueCodec is the concrete ValueCodec[COUNTvalueExtIEsExtField].
type COUNTvalueExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTvalueExtIEsExtField, error)
	encode  func(COUNTvalueExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTvalueExtIEsExtField, aper.DecodeState) (COUNTvalueExtIEsExtField, aper.Snapshot)
	compare func(COUNTvalueExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvalueExtIEsExtFieldValueCodec) New(value COUNTvalueExtIEsExtField) (COUNTvalueExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return COUNTvalueExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTvalueExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTvalueExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTvalueExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvalueExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTvalueExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTvalueExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTvalueExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTvalueExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTvalueExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvalueExtIEsExtFieldValueCodec) EncodeAPER(value COUNTvalueExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c COUNTvalueExtIEsExtFieldValueCodec) encodeBudgetValue(value COUNTvalueExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvalueExtIEsExtFieldValueCodec) encodeChanged(value COUNTvalueExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec is the concrete ValueCodec[COUNTvaluePDCPSNlength18ExtIEsExtField].
type COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtField, error)
	encode  func(COUNTvaluePDCPSNlength18ExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTvaluePDCPSNlength18ExtIEsExtField, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtField, aper.Snapshot)
	compare func(COUNTvaluePDCPSNlength18ExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) New(value COUNTvaluePDCPSNlength18ExtIEsExtField) (COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) EncodeAPER(value COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) encodeBudgetValue(value COUNTvaluePDCPSNlength18ExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) encodeChanged(value COUNTvaluePDCPSNlength18ExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGIdListItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CSGIdListItemExtIEsExtField].
type CSGIdListItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGIdListItemExtIEsExtField, error)
	encode  func(CSGIdListItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGIdListItemExtIEsExtField, aper.DecodeState) (CSGIdListItemExtIEsExtField, aper.Snapshot)
	compare func(CSGIdListItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGIdListItemExtIEsExtFieldValueCodec) New(value CSGIdListItemExtIEsExtField) (CSGIdListItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CSGIdListItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGIdListItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGIdListItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGIdListItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGIdListItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGIdListItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGIdListItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGIdListItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGIdListItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGIdListItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGIdListItemExtIEsExtFieldValueCodec) EncodeAPER(value CSGIdListItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CSGIdListItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CSGIdListItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGIdListItemExtIEsExtFieldValueCodec) encodeChanged(value CSGIdListItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGMembershipInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[CSGMembershipInfoExtIEsExtField].
type CSGMembershipInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGMembershipInfoExtIEsExtField, error)
	encode  func(CSGMembershipInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGMembershipInfoExtIEsExtField, aper.DecodeState) (CSGMembershipInfoExtIEsExtField, aper.Snapshot)
	compare func(CSGMembershipInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGMembershipInfoExtIEsExtFieldValueCodec) New(value CSGMembershipInfoExtIEsExtField) (CSGMembershipInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CSGMembershipInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGMembershipInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGMembershipInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGMembershipInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGMembershipInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGMembershipInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGMembershipInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGMembershipInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGMembershipInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGMembershipInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGMembershipInfoExtIEsExtFieldValueCodec) EncodeAPER(value CSGMembershipInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CSGMembershipInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value CSGMembershipInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGMembershipInfoExtIEsExtFieldValueCodec) encodeChanged(value CSGMembershipInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinEAIItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CancelledCellinEAIItemExtIEsExtField].
type CancelledCellinEAIItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtField, error)
	encode  func(CancelledCellinEAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinEAIItemExtIEsExtField, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtField, aper.Snapshot)
	compare func(CancelledCellinEAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinEAIItemExtIEsExtFieldValueCodec) New(value CancelledCellinEAIItemExtIEsExtField) (CancelledCellinEAIItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinEAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinEAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinEAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinEAIItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinEAIItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinEAIItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinEAIItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinEAIItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinEAIItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinEAIItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinEAIItemExtIEsExtFieldValueCodec) EncodeAPER(value CancelledCellinEAIItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CancelledCellinEAIItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CancelledCellinEAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinEAIItemExtIEsExtFieldValueCodec) encodeChanged(value CancelledCellinEAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinTAIItemExtIEsExtFieldValueCodec is the concrete ValueCodec[CancelledCellinTAIItemExtIEsExtField].
type CancelledCellinTAIItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtField, error)
	encode  func(CancelledCellinTAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinTAIItemExtIEsExtField, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtField, aper.Snapshot)
	compare func(CancelledCellinTAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinTAIItemExtIEsExtFieldValueCodec) New(value CancelledCellinTAIItemExtIEsExtField) (CancelledCellinTAIItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinTAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinTAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinTAIItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinTAIItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinTAIItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinTAIItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinTAIItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinTAIItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinTAIItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinTAIItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinTAIItemExtIEsExtFieldValueCodec) EncodeAPER(value CancelledCellinTAIItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CancelledCellinTAIItemExtIEsExtFieldValueCodec) encodeBudgetValue(value CancelledCellinTAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinTAIItemExtIEsExtFieldValueCodec) encodeChanged(value CancelledCellinTAIItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[Cdma2000OneXSRVCCInfoExtIEsExtField].
type Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtField, error)
	encode  func(Cdma2000OneXSRVCCInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Cdma2000OneXSRVCCInfoExtIEsExtField, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtField, aper.Snapshot)
	compare func(Cdma2000OneXSRVCCInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) New(value Cdma2000OneXSRVCCInfoExtIEsExtField) (Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) EncodeAPER(value Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value Cdma2000OneXSRVCCInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) encodeChanged(value Cdma2000OneXSRVCCInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellBasedMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[CellBasedMDTExtIEsExtField].
type CellBasedMDTExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellBasedMDTExtIEsExtField, error)
	encode  func(CellBasedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellBasedMDTExtIEsExtField, aper.DecodeState) (CellBasedMDTExtIEsExtField, aper.Snapshot)
	compare func(CellBasedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedMDTExtIEsExtFieldValueCodec) New(value CellBasedMDTExtIEsExtField) (CellBasedMDTExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return CellBasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedMDTExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedMDTExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedMDTExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedMDTExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedMDTExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedMDTExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedMDTExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedMDTExtIEsExtFieldValueCodec) EncodeAPER(value CellBasedMDTExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedMDTExtIEsExtFieldValueCodec) encodeBudgetValue(value CellBasedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedMDTExtIEsExtFieldValueCodec) encodeChanged(value CellBasedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AdditionalGUTIExtIEsExtContainerValueCodec is the concrete ValueCodec[AdditionalGUTIExtIEsExtContainer].
type AdditionalGUTIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AdditionalGUTIExtIEsExtContainer, error)
	encode  func(AdditionalGUTIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AdditionalGUTIExtIEsExtContainer, aper.DecodeState) (AdditionalGUTIExtIEsExtContainer, aper.Snapshot)
	compare func(AdditionalGUTIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AdditionalGUTIExtIEsExtContainerValueCodec) New(value AdditionalGUTIExtIEsExtContainer) (AdditionalGUTIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return AdditionalGUTIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AdditionalGUTIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AdditionalGUTIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AdditionalGUTIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AdditionalGUTIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AdditionalGUTIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AdditionalGUTIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AdditionalGUTIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AdditionalGUTIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AdditionalGUTIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AdditionalGUTIExtIEsExtContainerValueCodec) EncodeAPER(value AdditionalGUTIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AdditionalGUTIExtIEsExtContainerValueCodec) encodeBudgetValue(value AdditionalGUTIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AdditionalGUTIExtIEsExtContainerValueCodec) encodeChanged(value AdditionalGUTIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AllocationAndRetentionPriorityExtIEsExtContainerValueCodec is the concrete ValueCodec[AllocationAndRetentionPriorityExtIEsExtContainer].
type AllocationAndRetentionPriorityExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtContainer, error)
	encode  func(AllocationAndRetentionPriorityExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AllocationAndRetentionPriorityExtIEsExtContainer, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtContainer, aper.Snapshot)
	compare func(AllocationAndRetentionPriorityExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) New(value AllocationAndRetentionPriorityExtIEsExtContainer) (AllocationAndRetentionPriorityExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AllocationAndRetentionPriorityExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AllocationAndRetentionPriorityExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) EncodeAPER(value AllocationAndRetentionPriorityExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) encodeBudgetValue(value AllocationAndRetentionPriorityExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) encodeChanged(value AllocationAndRetentionPriorityExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AssistanceDataForPagingExtIEsExtContainerValueCodec is the concrete ValueCodec[AssistanceDataForPagingExtIEsExtContainer].
type AssistanceDataForPagingExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AssistanceDataForPagingExtIEsExtContainer, error)
	encode  func(AssistanceDataForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AssistanceDataForPagingExtIEsExtContainer, aper.DecodeState) (AssistanceDataForPagingExtIEsExtContainer, aper.Snapshot)
	compare func(AssistanceDataForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AssistanceDataForPagingExtIEsExtContainerValueCodec) New(value AssistanceDataForPagingExtIEsExtContainer) (AssistanceDataForPagingExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return AssistanceDataForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceDataForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceDataForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AssistanceDataForPagingExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AssistanceDataForPagingExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceDataForPagingExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AssistanceDataForPagingExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AssistanceDataForPagingExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AssistanceDataForPagingExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AssistanceDataForPagingExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AssistanceDataForPagingExtIEsExtContainerValueCodec) EncodeAPER(value AssistanceDataForPagingExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AssistanceDataForPagingExtIEsExtContainerValueCodec) encodeBudgetValue(value AssistanceDataForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AssistanceDataForPagingExtIEsExtContainerValueCodec) encodeChanged(value AssistanceDataForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec is the concrete ValueCodec[AssistanceDataForRecommendedCellsExtIEsExtContainer].
type AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtContainer, error)
	encode  func(AssistanceDataForRecommendedCellsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AssistanceDataForRecommendedCellsExtIEsExtContainer, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtContainer, aper.Snapshot)
	compare func(AssistanceDataForRecommendedCellsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) New(value AssistanceDataForRecommendedCellsExtIEsExtContainer) (AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) EncodeAPER(value AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) encodeBudgetValue(value AssistanceDataForRecommendedCellsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) encodeChanged(value AssistanceDataForRecommendedCellsExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItemExtIEsExtContainer].
type BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtContainer, error)
	encode  func(BearersSubjectToDLDiscardingItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtContainer, aper.Snapshot)
	compare func(BearersSubjectToDLDiscardingItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) New(value BearersSubjectToDLDiscardingItemExtIEsExtContainer) (BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer].
type BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, error)
	encode  func(BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, aper.Snapshot)
	compare func(BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) New(value BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer) (BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[BluetoothMeasurementConfigurationExtIEsExtContainer].
type BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtContainer, error)
	encode  func(BluetoothMeasurementConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BluetoothMeasurementConfigurationExtIEsExtContainer, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(BluetoothMeasurementConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) New(value BluetoothMeasurementConfigurationExtIEsExtContainer) (BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value BluetoothMeasurementConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) encodeChanged(value BluetoothMeasurementConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CGIExtIEsExtContainerValueCodec is the concrete ValueCodec[CGIExtIEsExtContainer].
type CGIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CGIExtIEsExtContainer, error)
	encode  func(CGIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CGIExtIEsExtContainer, aper.DecodeState) (CGIExtIEsExtContainer, aper.Snapshot)
	compare func(CGIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CGIExtIEsExtContainerValueCodec) New(value CGIExtIEsExtContainer) (CGIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CGIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CGIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CGIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CGIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CGIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CGIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CGIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CGIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CGIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CGIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CGIExtIEsExtContainerValueCodec) EncodeAPER(value CGIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CGIExtIEsExtContainerValueCodec) encodeBudgetValue(value CGIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CGIExtIEsExtContainerValueCodec) encodeChanged(value CGIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CNTypeRestrictionsItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CNTypeRestrictionsItemExtIEsExtContainer].
type CNTypeRestrictionsItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtContainer, error)
	encode  func(CNTypeRestrictionsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CNTypeRestrictionsItemExtIEsExtContainer, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtContainer, aper.Snapshot)
	compare func(CNTypeRestrictionsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CNTypeRestrictionsItemExtIEsExtContainerValueCodec) New(value CNTypeRestrictionsItemExtIEsExtContainer) (CNTypeRestrictionsItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CNTypeRestrictionsItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CNTypeRestrictionsItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CNTypeRestrictionsItemExtIEsExtContainerValueCodec) EncodeAPER(value CNTypeRestrictionsItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CNTypeRestrictionsItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CNTypeRestrictionsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CNTypeRestrictionsItemExtIEsExtContainerValueCodec) encodeChanged(value CNTypeRestrictionsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTValueExtendedExtIEsExtContainerValueCodec is the concrete ValueCodec[COUNTValueExtendedExtIEsExtContainer].
type COUNTValueExtendedExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTValueExtendedExtIEsExtContainer, error)
	encode  func(COUNTValueExtendedExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTValueExtendedExtIEsExtContainer, aper.DecodeState) (COUNTValueExtendedExtIEsExtContainer, aper.Snapshot)
	compare func(COUNTValueExtendedExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTValueExtendedExtIEsExtContainerValueCodec) New(value COUNTValueExtendedExtIEsExtContainer) (COUNTValueExtendedExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return COUNTValueExtendedExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTValueExtendedExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTValueExtendedExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTValueExtendedExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTValueExtendedExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTValueExtendedExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTValueExtendedExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTValueExtendedExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTValueExtendedExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTValueExtendedExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTValueExtendedExtIEsExtContainerValueCodec) EncodeAPER(value COUNTValueExtendedExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c COUNTValueExtendedExtIEsExtContainerValueCodec) encodeBudgetValue(value COUNTValueExtendedExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTValueExtendedExtIEsExtContainerValueCodec) encodeChanged(value COUNTValueExtendedExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTvalueExtIEsExtContainerValueCodec is the concrete ValueCodec[COUNTvalueExtIEsExtContainer].
type COUNTvalueExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTvalueExtIEsExtContainer, error)
	encode  func(COUNTvalueExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTvalueExtIEsExtContainer, aper.DecodeState) (COUNTvalueExtIEsExtContainer, aper.Snapshot)
	compare func(COUNTvalueExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvalueExtIEsExtContainerValueCodec) New(value COUNTvalueExtIEsExtContainer) (COUNTvalueExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return COUNTvalueExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTvalueExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTvalueExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTvalueExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvalueExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTvalueExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTvalueExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTvalueExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTvalueExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTvalueExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvalueExtIEsExtContainerValueCodec) EncodeAPER(value COUNTvalueExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c COUNTvalueExtIEsExtContainerValueCodec) encodeBudgetValue(value COUNTvalueExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvalueExtIEsExtContainerValueCodec) encodeChanged(value COUNTvalueExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec is the concrete ValueCodec[COUNTvaluePDCPSNlength18ExtIEsExtContainer].
type COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtContainer, error)
	encode  func(COUNTvaluePDCPSNlength18ExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTvaluePDCPSNlength18ExtIEsExtContainer, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtContainer, aper.Snapshot)
	compare func(COUNTvaluePDCPSNlength18ExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) New(value COUNTvaluePDCPSNlength18ExtIEsExtContainer) (COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) EncodeAPER(value COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) encodeBudgetValue(value COUNTvaluePDCPSNlength18ExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) encodeChanged(value COUNTvaluePDCPSNlength18ExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGIdListItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CSGIdListItemExtIEsExtContainer].
type CSGIdListItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGIdListItemExtIEsExtContainer, error)
	encode  func(CSGIdListItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGIdListItemExtIEsExtContainer, aper.DecodeState) (CSGIdListItemExtIEsExtContainer, aper.Snapshot)
	compare func(CSGIdListItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGIdListItemExtIEsExtContainerValueCodec) New(value CSGIdListItemExtIEsExtContainer) (CSGIdListItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CSGIdListItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGIdListItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGIdListItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGIdListItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGIdListItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGIdListItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGIdListItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGIdListItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGIdListItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGIdListItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGIdListItemExtIEsExtContainerValueCodec) EncodeAPER(value CSGIdListItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CSGIdListItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CSGIdListItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGIdListItemExtIEsExtContainerValueCodec) encodeChanged(value CSGIdListItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGMembershipInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[CSGMembershipInfoExtIEsExtContainer].
type CSGMembershipInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGMembershipInfoExtIEsExtContainer, error)
	encode  func(CSGMembershipInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGMembershipInfoExtIEsExtContainer, aper.DecodeState) (CSGMembershipInfoExtIEsExtContainer, aper.Snapshot)
	compare func(CSGMembershipInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGMembershipInfoExtIEsExtContainerValueCodec) New(value CSGMembershipInfoExtIEsExtContainer) (CSGMembershipInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CSGMembershipInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGMembershipInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGMembershipInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGMembershipInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGMembershipInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGMembershipInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGMembershipInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGMembershipInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGMembershipInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGMembershipInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGMembershipInfoExtIEsExtContainerValueCodec) EncodeAPER(value CSGMembershipInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CSGMembershipInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value CSGMembershipInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGMembershipInfoExtIEsExtContainerValueCodec) encodeChanged(value CSGMembershipInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinEAIItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CancelledCellinEAIItemExtIEsExtContainer].
type CancelledCellinEAIItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtContainer, error)
	encode  func(CancelledCellinEAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinEAIItemExtIEsExtContainer, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtContainer, aper.Snapshot)
	compare func(CancelledCellinEAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinEAIItemExtIEsExtContainerValueCodec) New(value CancelledCellinEAIItemExtIEsExtContainer) (CancelledCellinEAIItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinEAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinEAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinEAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinEAIItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinEAIItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinEAIItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinEAIItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinEAIItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinEAIItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinEAIItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinEAIItemExtIEsExtContainerValueCodec) EncodeAPER(value CancelledCellinEAIItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CancelledCellinEAIItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CancelledCellinEAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinEAIItemExtIEsExtContainerValueCodec) encodeChanged(value CancelledCellinEAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinTAIItemExtIEsExtContainerValueCodec is the concrete ValueCodec[CancelledCellinTAIItemExtIEsExtContainer].
type CancelledCellinTAIItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtContainer, error)
	encode  func(CancelledCellinTAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinTAIItemExtIEsExtContainer, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtContainer, aper.Snapshot)
	compare func(CancelledCellinTAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinTAIItemExtIEsExtContainerValueCodec) New(value CancelledCellinTAIItemExtIEsExtContainer) (CancelledCellinTAIItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinTAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinTAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinTAIItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinTAIItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinTAIItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinTAIItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinTAIItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinTAIItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinTAIItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinTAIItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinTAIItemExtIEsExtContainerValueCodec) EncodeAPER(value CancelledCellinTAIItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CancelledCellinTAIItemExtIEsExtContainerValueCodec) encodeBudgetValue(value CancelledCellinTAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinTAIItemExtIEsExtContainerValueCodec) encodeChanged(value CancelledCellinTAIItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[Cdma2000OneXSRVCCInfoExtIEsExtContainer].
type Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtContainer, error)
	encode  func(Cdma2000OneXSRVCCInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Cdma2000OneXSRVCCInfoExtIEsExtContainer, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtContainer, aper.Snapshot)
	compare func(Cdma2000OneXSRVCCInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) New(value Cdma2000OneXSRVCCInfoExtIEsExtContainer) (Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) EncodeAPER(value Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value Cdma2000OneXSRVCCInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) encodeChanged(value Cdma2000OneXSRVCCInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellBasedMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[CellBasedMDTExtIEsExtContainer].
type CellBasedMDTExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellBasedMDTExtIEsExtContainer, error)
	encode  func(CellBasedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellBasedMDTExtIEsExtContainer, aper.DecodeState) (CellBasedMDTExtIEsExtContainer, aper.Snapshot)
	compare func(CellBasedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedMDTExtIEsExtContainerValueCodec) New(value CellBasedMDTExtIEsExtContainer) (CellBasedMDTExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CellBasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedMDTExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedMDTExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedMDTExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedMDTExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedMDTExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedMDTExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedMDTExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedMDTExtIEsExtContainerValueCodec) EncodeAPER(value CellBasedMDTExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedMDTExtIEsExtContainerValueCodec) encodeBudgetValue(value CellBasedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedMDTExtIEsExtContainerValueCodec) encodeChanged(value CellBasedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellBasedQMCExtIEsExtContainerValueCodec is the concrete ValueCodec[CellBasedQMCExtIEsExtContainer].
type CellBasedQMCExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellBasedQMCExtIEsExtContainer, error)
	encode  func(CellBasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellBasedQMCExtIEsExtContainer, aper.DecodeState) (CellBasedQMCExtIEsExtContainer, aper.Snapshot)
	compare func(CellBasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedQMCExtIEsExtContainerValueCodec) New(value CellBasedQMCExtIEsExtContainer) (CellBasedQMCExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return CellBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedQMCExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedQMCExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedQMCExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedQMCExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedQMCExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedQMCExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedQMCExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedQMCExtIEsExtContainerValueCodec) EncodeAPER(value CellBasedQMCExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedQMCExtIEsExtContainerValueCodec) encodeBudgetValue(value CellBasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedQMCExtIEsExtContainerValueCodec) encodeChanged(value CellBasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AdditionalGUTIExtIEsExtFieldAPERValue is the concrete APERValue[AdditionalGUTIExtIEsExtField].
type AdditionalGUTIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AdditionalGUTIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AdditionalGUTIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AdditionalGUTIExtIEsExtFieldAPERValue) WithoutReplay() AdditionalGUTIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AllocationAndRetentionPriorityExtIEsExtFieldAPERValue is the concrete APERValue[AllocationAndRetentionPriorityExtIEsExtField].
type AllocationAndRetentionPriorityExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AllocationAndRetentionPriorityExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AllocationAndRetentionPriorityExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AllocationAndRetentionPriorityExtIEsExtFieldAPERValue) WithoutReplay() AllocationAndRetentionPriorityExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceDataForPagingExtIEsExtFieldAPERValue is the concrete APERValue[AssistanceDataForPagingExtIEsExtField].
type AssistanceDataForPagingExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AssistanceDataForPagingExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AssistanceDataForPagingExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForPagingExtIEsExtFieldAPERValue) WithoutReplay() AssistanceDataForPagingExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue is the concrete APERValue[AssistanceDataForRecommendedCellsExtIEsExtField].
type AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AssistanceDataForRecommendedCellsExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue) WithoutReplay() AssistanceDataForRecommendedCellsExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItemExtIEsExtField].
type BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToDLDiscardingItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItemExtIEsExtField].
type BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToEarlyStatusTransferItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[BluetoothMeasurementConfigurationExtIEsExtField].
type BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BluetoothMeasurementConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue) WithoutReplay() BluetoothMeasurementConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CGIExtIEsExtFieldAPERValue is the concrete APERValue[CGIExtIEsExtField].
type CGIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CGIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CGIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CGIExtIEsExtFieldAPERValue) WithoutReplay() CGIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CNTypeRestrictionsItemExtIEsExtFieldAPERValue is the concrete APERValue[CNTypeRestrictionsItemExtIEsExtField].
type CNTypeRestrictionsItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CNTypeRestrictionsItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CNTypeRestrictionsItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsItemExtIEsExtFieldAPERValue) WithoutReplay() CNTypeRestrictionsItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTValueExtendedExtIEsExtFieldAPERValue is the concrete APERValue[COUNTValueExtendedExtIEsExtField].
type COUNTValueExtendedExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         COUNTValueExtendedExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTValueExtendedExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTValueExtendedExtIEsExtFieldAPERValue) WithoutReplay() COUNTValueExtendedExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvalueExtIEsExtFieldAPERValue is the concrete APERValue[COUNTvalueExtIEsExtField].
type COUNTvalueExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         COUNTvalueExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvalueExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvalueExtIEsExtFieldAPERValue) WithoutReplay() COUNTvalueExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue is the concrete APERValue[COUNTvaluePDCPSNlength18ExtIEsExtField].
type COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         COUNTvaluePDCPSNlength18ExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue) WithoutReplay() COUNTvaluePDCPSNlength18ExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGIdListItemExtIEsExtFieldAPERValue is the concrete APERValue[CSGIdListItemExtIEsExtField].
type CSGIdListItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CSGIdListItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGIdListItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListItemExtIEsExtFieldAPERValue) WithoutReplay() CSGIdListItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGMembershipInfoExtIEsExtFieldAPERValue is the concrete APERValue[CSGMembershipInfoExtIEsExtField].
type CSGMembershipInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CSGMembershipInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGMembershipInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGMembershipInfoExtIEsExtFieldAPERValue) WithoutReplay() CSGMembershipInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinEAIItemExtIEsExtFieldAPERValue is the concrete APERValue[CancelledCellinEAIItemExtIEsExtField].
type CancelledCellinEAIItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CancelledCellinEAIItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinEAIItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinEAIItemExtIEsExtFieldAPERValue) WithoutReplay() CancelledCellinEAIItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinTAIItemExtIEsExtFieldAPERValue is the concrete APERValue[CancelledCellinTAIItemExtIEsExtField].
type CancelledCellinTAIItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CancelledCellinTAIItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinTAIItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinTAIItemExtIEsExtFieldAPERValue) WithoutReplay() CancelledCellinTAIItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue is the concrete APERValue[Cdma2000OneXSRVCCInfoExtIEsExtField].
type Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         Cdma2000OneXSRVCCInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue) WithoutReplay() Cdma2000OneXSRVCCInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellBasedMDTExtIEsExtFieldAPERValue is the concrete APERValue[CellBasedMDTExtIEsExtField].
type CellBasedMDTExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellBasedMDTExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedMDTExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedMDTExtIEsExtFieldAPERValue) WithoutReplay() CellBasedMDTExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AdditionalGUTIExtIEsExtContainerAPERValue is the concrete APERValue[AdditionalGUTIExtIEsExtContainer].
type AdditionalGUTIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AdditionalGUTIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AdditionalGUTIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AdditionalGUTIExtIEsExtContainerAPERValue) WithoutReplay() AdditionalGUTIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AllocationAndRetentionPriorityExtIEsExtContainerAPERValue is the concrete APERValue[AllocationAndRetentionPriorityExtIEsExtContainer].
type AllocationAndRetentionPriorityExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AllocationAndRetentionPriorityExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AllocationAndRetentionPriorityExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AllocationAndRetentionPriorityExtIEsExtContainerAPERValue) WithoutReplay() AllocationAndRetentionPriorityExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceDataForPagingExtIEsExtContainerAPERValue is the concrete APERValue[AssistanceDataForPagingExtIEsExtContainer].
type AssistanceDataForPagingExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AssistanceDataForPagingExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AssistanceDataForPagingExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForPagingExtIEsExtContainerAPERValue) WithoutReplay() AssistanceDataForPagingExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue is the concrete APERValue[AssistanceDataForRecommendedCellsExtIEsExtContainer].
type AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         AssistanceDataForRecommendedCellsExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue) WithoutReplay() AssistanceDataForRecommendedCellsExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItemExtIEsExtContainer].
type BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToDLDiscardingItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer].
type BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[BluetoothMeasurementConfigurationExtIEsExtContainer].
type BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BluetoothMeasurementConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue) WithoutReplay() BluetoothMeasurementConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CGIExtIEsExtContainerAPERValue is the concrete APERValue[CGIExtIEsExtContainer].
type CGIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CGIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CGIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CGIExtIEsExtContainerAPERValue) WithoutReplay() CGIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CNTypeRestrictionsItemExtIEsExtContainerAPERValue is the concrete APERValue[CNTypeRestrictionsItemExtIEsExtContainer].
type CNTypeRestrictionsItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CNTypeRestrictionsItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CNTypeRestrictionsItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsItemExtIEsExtContainerAPERValue) WithoutReplay() CNTypeRestrictionsItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTValueExtendedExtIEsExtContainerAPERValue is the concrete APERValue[COUNTValueExtendedExtIEsExtContainer].
type COUNTValueExtendedExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         COUNTValueExtendedExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTValueExtendedExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTValueExtendedExtIEsExtContainerAPERValue) WithoutReplay() COUNTValueExtendedExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvalueExtIEsExtContainerAPERValue is the concrete APERValue[COUNTvalueExtIEsExtContainer].
type COUNTvalueExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         COUNTvalueExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvalueExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvalueExtIEsExtContainerAPERValue) WithoutReplay() COUNTvalueExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue is the concrete APERValue[COUNTvaluePDCPSNlength18ExtIEsExtContainer].
type COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         COUNTvaluePDCPSNlength18ExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue) WithoutReplay() COUNTvaluePDCPSNlength18ExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGIdListItemExtIEsExtContainerAPERValue is the concrete APERValue[CSGIdListItemExtIEsExtContainer].
type CSGIdListItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CSGIdListItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGIdListItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListItemExtIEsExtContainerAPERValue) WithoutReplay() CSGIdListItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGMembershipInfoExtIEsExtContainerAPERValue is the concrete APERValue[CSGMembershipInfoExtIEsExtContainer].
type CSGMembershipInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CSGMembershipInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGMembershipInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGMembershipInfoExtIEsExtContainerAPERValue) WithoutReplay() CSGMembershipInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinEAIItemExtIEsExtContainerAPERValue is the concrete APERValue[CancelledCellinEAIItemExtIEsExtContainer].
type CancelledCellinEAIItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CancelledCellinEAIItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinEAIItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinEAIItemExtIEsExtContainerAPERValue) WithoutReplay() CancelledCellinEAIItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinTAIItemExtIEsExtContainerAPERValue is the concrete APERValue[CancelledCellinTAIItemExtIEsExtContainer].
type CancelledCellinTAIItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CancelledCellinTAIItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinTAIItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinTAIItemExtIEsExtContainerAPERValue) WithoutReplay() CancelledCellinTAIItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue is the concrete APERValue[Cdma2000OneXSRVCCInfoExtIEsExtContainer].
type Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         Cdma2000OneXSRVCCInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue) WithoutReplay() Cdma2000OneXSRVCCInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellBasedMDTExtIEsExtContainerAPERValue is the concrete APERValue[CellBasedMDTExtIEsExtContainer].
type CellBasedMDTExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellBasedMDTExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedMDTExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedMDTExtIEsExtContainerAPERValue) WithoutReplay() CellBasedMDTExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellBasedQMCExtIEsExtContainerAPERValue is the concrete APERValue[CellBasedQMCExtIEsExtContainer].
type CellBasedQMCExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellBasedQMCExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedQMCExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedQMCExtIEsExtContainerAPERValue) WithoutReplay() CellBasedQMCExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
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
func BridgeCompareS1APBPLMNs(v *s00.BPLMNs, s *aper.SemanticComparison) {
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
			BridgeCompareS1APPLMNidentity(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APENBIndirectX2TransportLayerAddresses(v *s00.ENBIndirectX2TransportLayerAddresses, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTransportLayerAddress(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APENBX2GTPTLAs(v *s00.ENBX2GTPTLAs, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTransportLayerAddress(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APENBX2TLAs(v *s00.ENBX2TLAs, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTransportLayerAddress(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEPLMNs(v *s00.EPLMNs, s *aper.SemanticComparison) {
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
			BridgeCompareS1APPLMNidentity(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APForbiddenTACs(v *s00.ForbiddenTACs, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTAC(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMDTPLMNList(v *s00.MDTPLMNList, s *aper.SemanticComparison) {
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
			BridgeCompareS1APPLMNidentity(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPLMNListforQMC(v *s00.PLMNListforQMC, s *aper.SemanticComparison) {
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
			BridgeCompareS1APPLMNidentity(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPLMNidentity(v *s00.PLMNidentity, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APTBCDSTRING(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APQCI(v *s00.QCI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRAC(v *s00.RAC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRACSIndication(v *s00.RACSIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRANUENGAPID(v *s00.RANUENGAPID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRATType(v *s00.RATType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRIMInformation(v *s00.RIMInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRNCID(v *s00.RNCID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRRCContainer(v *s00.RRCContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRRCEstablishmentCause(v *s00.RRCEstablishmentCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRange(v *s00.Range, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReceiveStatusOfULPDCPSDUsExtended(v *s00.ReceiveStatusOfULPDCPSDUsExtended, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(v *s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReceiveStatusofULPDCPSDUs(v *s00.ReceiveStatusofULPDCPSDUs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRelativeMMECapacity(v *s00.RelativeMMECapacity, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRelayNodeIndicator(v *s00.RelayNodeIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRepetitionPeriod(v *s00.RepetitionPeriod, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReportAmountMDT(v *s00.ReportAmountMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReportArea(v *s00.ReportArea, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReportIntervalMDT(v *s00.ReportIntervalMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRequestTypeAdditionalInfo(v *s00.RequestTypeAdditionalInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APRequestTypeExtIEsValue(v *RequestTypeExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(298):
			{
				f := s.Begin()
				s.Bool(v.rowRequestTypeAdditionalInfo == nil)
				if v.rowRequestTypeAdditionalInfo != nil {
					s00.BridgeCaptureS1APRequestTypeAdditionalInfo(v.rowRequestTypeAdditionalInfo, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RequestTypeExtIEsValue) captureSemantics(s aper.SemanticCapture) RequestTypeExtIEsValue {
	BridgeCaptureS1APRequestTypeExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APRequestTypeExtIEsValue(v *RequestTypeExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(298):
			{
				f := s.Begin()
				s.Bool(v.rowRequestTypeAdditionalInfo == nil)
				if v.rowRequestTypeAdditionalInfo != nil {
					BridgeCompareS1APRequestTypeAdditionalInfo(v.rowRequestTypeAdditionalInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RequestTypeExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APRequestTypeExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APResetAll(v *s00.ResetAll, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRoutingID(v *s00.RoutingID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APS1APIEsMobilityInformation(v *s00.S1APIEsMobilityInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSONInformationRequest(v *s00.SONInformationRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSONtransferApplicationIdentity(v *s00.SONtransferApplicationIdentity, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSRVCCHOIndication(v *s00.SRVCCHOIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSRVCCOperationNotPossible(v *s00.SRVCCOperationNotPossible, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSRVCCOperationPossible(v *s00.SRVCCOperationPossible, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSecondaryRATDataUsageRequest(v *s00.SecondaryRATDataUsageRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSecondaryRATType(v *s00.SecondaryRATType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSecurityKey(v *s00.SecurityKey, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSensorMeasConfig(v *s00.SensorMeasConfig, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSerialNumber(v *s00.SerialNumber, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APServedGroupIDs(v *s00.ServedGroupIDs, s *aper.SemanticComparison) {
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
			s02.BridgeCompareS1APMMEGroupID(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APServedMMECs(v *s00.ServedMMECs, s *aper.SemanticComparison) {
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
			s02.BridgeCompareS1APMMECode(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APServedPLMNs(v *s00.ServedPLMNs, s *aper.SemanticComparison) {
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
			BridgeCompareS1APPLMNidentity(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APServiceType(v *s00.ServiceType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSonTransferIEsMobilityInformation(v *s00.SonTransferIEsMobilityInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSourceBSSToTargetBSSTransparentContainer(v *s00.SourceBSSToTargetBSSTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSourceNgRanNodeToTargetNgRanNodeTransparentContainer(v *s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSourceOfUEActivityBehaviourInformation(v *s00.SourceOfUEActivityBehaviourInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSourceRNCToTargetRNCTransparentContainer(v *s00.SourceRNCToTargetRNCTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSourceToTargetTransparentContainer(v *s00.SourceToTargetTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APStratumLevel(v *s00.StratumLevel, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APSubscriberProfileIDforRFP(v *s00.SubscriberProfileIDforRFP, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSupportedTAsItemExtIEsValue(v *SupportedTAsItemExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(232):
			{
				f := s.Begin()
				s.Bool(v.rowRATType == nil)
				if v.rowRATType != nil {
					s00.BridgeCaptureS1APRATType(v.rowRATType, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SupportedTAsItemExtIEsValue) captureSemantics(s aper.SemanticCapture) SupportedTAsItemExtIEsValue {
	BridgeCaptureS1APSupportedTAsItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APSupportedTAsItemExtIEsValue(v *SupportedTAsItemExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(232):
			{
				f := s.Begin()
				s.Bool(v.rowRATType == nil)
				if v.rowRATType != nil {
					BridgeCompareS1APRATType(v.rowRATType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SupportedTAsItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSupportedTAsItemExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APSynchronisationStatus(v *s00.SynchronisationStatus, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTAC(v *s00.TAC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTACListInLTENTN(v *s00.TACListInLTENTN, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTAC(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTAListforMDT(v *s00.TAListforMDT, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTAC(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTAListforQMC(v *s00.TAListforQMC, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTAC(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTBCDSTRING(v *s00.TBCDSTRING, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTargetBSSToSourceBSSTransparentContainer(v *s00.TargetBSSToSourceBSSTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTargetNgRanNodeToSourceNgRanNodeTransparentContainer(v *s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTargetRNCToSourceRNCTransparentContainer(v *s00.TargetRNCToSourceRNCTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTargetToSourceTransparentContainer(v *s00.TargetToSourceTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APThresholdRSRP(v *s00.ThresholdRSRP, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APThresholdRSRQ(v *s00.ThresholdRSRQ, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTimeRefDistribution(v *s00.TimeRefDistribution, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTimeSinceSecondaryNodeRelease(v *s00.TimeSinceSecondaryNodeRelease, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTimeToTrigger(v *s00.TimeToTrigger, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTimeToWait(v *s00.TimeToWait, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTimeUEStayedInCell(v *s00.TimeUEStayedInCell, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTimeUEStayedInCellEnhancedGranularity(v *s00.TimeUEStayedInCellEnhancedGranularity, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTraceDepth(v *s00.TraceDepth, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTrafficLoadReductionIndication(v *s00.TrafficLoadReductionIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTransportLayerAddress(v *s00.TransportLayerAddress, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTriggeringMessage(v *s00.TriggeringMessage, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTypeOfError(v *s00.TypeOfError, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APUEAppLayerMeasConfigExtIEsValue(v *UEAppLayerMeasConfigExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(276):
			{
				f := s.Begin()
				s.Bool(v.rowServiceType == nil)
				if v.rowServiceType != nil {
					s00.BridgeCaptureS1APServiceType(v.rowServiceType, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEAppLayerMeasConfigExtIEsValue) captureSemantics(s aper.SemanticCapture) UEAppLayerMeasConfigExtIEsValue {
	BridgeCaptureS1APUEAppLayerMeasConfigExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APUEAppLayerMeasConfigExtIEsValue(v *UEAppLayerMeasConfigExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(276):
			{
				f := s.Begin()
				s.Bool(v.rowServiceType == nil)
				if v.rowServiceType != nil {
					BridgeCompareS1APServiceType(v.rowServiceType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEAppLayerMeasConfigExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEAppLayerMeasConfigExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APUEApplicationLayerMeasurementCapability(v *s00.UEApplicationLayerMeasurementCapability, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUECapabilityInfoRequest(v *s00.UECapabilityInfoRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUEHistoryInformationFromTheUE(v *s00.UEHistoryInformationFromTheUE, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUEIdentityIndexValue(v *s00.UEIdentityIndexValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUERLFReportContainer(v *s00.UERLFReportContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUERLFReportContainerForExtendedBands(v *s00.UERLFReportContainerForExtendedBands, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUERadioCapability(v *s00.UERadioCapability, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUERadioCapabilityForPaging(v *s00.UERadioCapabilityForPaging, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUERadioCapabilityID(v *s00.UERadioCapabilityID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APUERadioCapabilityIDMappingRequestIEValue(v *UERadioCapabilityIDMappingRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s00.BridgeCaptureS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityIDMappingRequestIEValue) captureSemantics(s aper.SemanticCapture) UERadioCapabilityIDMappingRequestIEValue {
	BridgeCaptureS1APUERadioCapabilityIDMappingRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUERadioCapabilityIDMappingRequestIEValue(v *UERadioCapabilityIDMappingRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityIDMappingRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUERadioCapabilityIDMappingRequestIEValue(&v, &s)
	return s
}
func BridgeCompareS1APUERetentionInformation(v *s00.UERetentionInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUEUsageType(v *s00.UEUsageType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(v *s00.UEUserPlaneCIoTSupportIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APULNASCount(v *s00.ULNASCount, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APULNASMAC(v *s00.ULNASMAC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APURIAddress(v *s00.URIAddress, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.String((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APUnlicensedSpectrumRestriction(v *s00.UnlicensedSpectrumRestriction, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APVehicleUE(v *s00.VehicleUE, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APVoiceSupportMatchIndicator(v *s00.VoiceSupportMatchIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APWLANMeasConfig(v *s00.WLANMeasConfig, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APWLANMeasConfigNameList(v *s00.WLANMeasConfigNameList, s *aper.SemanticComparison) {
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
			BridgeCompareS1APWLANName(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APWLANName(v *s00.WLANName, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APWUSAssistanceInformationExtIEsValue(v *WUSAssistanceInformationExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v WUSAssistanceInformationExtIEsValue) captureSemantics(s aper.SemanticCapture) WUSAssistanceInformationExtIEsValue {
	BridgeCaptureS1APWUSAssistanceInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APWUSAssistanceInformationExtIEsValue(v *WUSAssistanceInformationExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v WUSAssistanceInformationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APWUSAssistanceInformationExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APWarningAreaCoordinates(v *s00.WarningAreaCoordinates, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APWarningMessageContents(v *s00.WarningMessageContents, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APWarningSecurityInfo(v *s00.WarningSecurityInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APWarningType(v *s00.WarningType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}

type RequestTypeExtIEsValue struct {
	id                           s00.ProtocolIEID
	received                     aper.WireSpan
	replay                       aper.Snapshot
	opaque                       aper.OpaqueOpenType
	isOpaque                     bool
	rowRequestTypeAdditionalInfo *s00.RequestTypeAdditionalInfo
}

func (v RequestTypeExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(298):
		return v.rowRequestTypeAdditionalInfo != nil
	}
	return false
}

// Opaque returns the retained opaque open value of RequestTypeExtIEsValue and reports whether the opaque alternative is selected.
func (v *RequestTypeExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (RequestTypeExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestType-ExtIEs"}}
}
func (RequestTypeExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(298):
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

// AsRequestTypeAdditionalInfo returns the selected RequestTypeAdditionalInfo value of RequestTypeExtIEsValue and reports whether that alternative is active.
func (v *RequestTypeExtIEsValue) AsRequestTypeAdditionalInfo() (*s00.RequestTypeAdditionalInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(298) || v.rowRequestTypeAdditionalInfo == nil {
		return nil, false
	}
	return v.rowRequestTypeAdditionalInfo, true
}
func (v RequestTypeExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (RequestTypeExtIEsValue, error) {
	out := RequestTypeExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(298):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "RequestTypeAdditionalInfo"})
		value := s00.RequestTypeAdditionalInfo(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RequestTypeAdditionalInfo:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRequestTypeAdditionalInfo = &value
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
func (v RequestTypeExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v RequestTypeExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(298):
		if v.rowRequestTypeAdditionalInfo == nil {
			return nil, fmt.Errorf("%s missing value", "RequestType-ExtIEs.id-RequestTypeAdditionalInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRequestTypeAdditionalInfo), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "RequestTypeExtIEsValue:", v.id)
	}
}

type SupportedTAsItemExtIEsValue struct {
	id         s00.ProtocolIEID
	received   aper.WireSpan
	replay     aper.Snapshot
	opaque     aper.OpaqueOpenType
	isOpaque   bool
	rowRATType *s00.RATType
}

func (v SupportedTAsItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(232):
		return v.rowRATType != nil
	}
	return false
}

// Opaque returns the retained opaque open value of SupportedTAsItemExtIEsValue and reports whether the opaque alternative is selected.
func (v *SupportedTAsItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SupportedTAsItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SupportedTAs-Item-ExtIEs"}}
}
func (SupportedTAsItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(232):
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

// AsRATType returns the selected RATType value of SupportedTAsItemExtIEsValue and reports whether that alternative is active.
func (v *SupportedTAsItemExtIEsValue) AsRATType() (*s00.RATType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(232) || v.rowRATType == nil {
		return nil, false
	}
	return v.rowRATType, true
}
func (v SupportedTAsItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SupportedTAsItemExtIEsValue, error) {
	out := SupportedTAsItemExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(232):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 8, Path: "RATType"})
		value := s00.RATType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RATType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRATType = &value
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
func (v SupportedTAsItemExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v SupportedTAsItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(232):
		if v.rowRATType == nil {
			return nil, fmt.Errorf("%s missing value", "SupportedTAs-Item-ExtIEs.id-RAT-Type:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRATType), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SupportedTAsItemExtIEsValue:", v.id)
	}
}

type UEAppLayerMeasConfigExtIEsValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowServiceType *s00.ServiceType
}

func (v UEAppLayerMeasConfigExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(276):
		return v.rowServiceType != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEAppLayerMeasConfigExtIEsValue and reports whether the opaque alternative is selected.
func (v *UEAppLayerMeasConfigExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEAppLayerMeasConfigExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAppLayerMeasConfig-ExtIEs"}}
}
func (UEAppLayerMeasConfigExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(276):
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

// AsServiceType returns the selected ServiceType value of UEAppLayerMeasConfigExtIEsValue and reports whether that alternative is active.
func (v *UEAppLayerMeasConfigExtIEsValue) AsServiceType() (*s00.ServiceType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(276) || v.rowServiceType == nil {
		return nil, false
	}
	return v.rowServiceType, true
}
func (v UEAppLayerMeasConfigExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEAppLayerMeasConfigExtIEsValue, error) {
	out := UEAppLayerMeasConfigExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(276):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ServiceType"})
		value := s00.ServiceType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ServiceType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowServiceType = &value
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
func (v UEAppLayerMeasConfigExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEAppLayerMeasConfigExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(276):
		if v.rowServiceType == nil {
			return nil, fmt.Errorf("%s missing value", "UEAppLayerMeasConfig-ExtIEs.id-serviceType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowServiceType), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEAppLayerMeasConfigExtIEsValue:", v.id)
	}
}

type WUSAssistanceInformationExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v WUSAssistanceInformationExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}

// Opaque returns the retained opaque open value of WUSAssistanceInformationExtIEsValue and reports whether the opaque alternative is selected.
func (v *WUSAssistanceInformationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (WUSAssistanceInformationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WUS-Assistance-Information-ExtIEs"}}
}
func (WUSAssistanceInformationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
func (v WUSAssistanceInformationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (WUSAssistanceInformationExtIEsValue, error) {
	out := WUSAssistanceInformationExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v WUSAssistanceInformationExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v WUSAssistanceInformationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "WUSAssistanceInformationExtIEsValue:", v.id)
	}
}

type UERadioCapabilityIDMappingRequestIEValue struct {
	id                     s00.ProtocolIEID
	received               aper.WireSpan
	replay                 aper.Snapshot
	opaque                 aper.OpaqueOpenType
	isOpaque               bool
	rowUERadioCapabilityID *s00.UERadioCapabilityID
}

func (v UERadioCapabilityIDMappingRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UERadioCapabilityIDMappingRequestIEValue and reports whether the opaque alternative is selected.
func (v *UERadioCapabilityIDMappingRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UERadioCapabilityIDMappingRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingRequestIEs"}}
}
func (UERadioCapabilityIDMappingRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(314):
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

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of UERadioCapabilityIDMappingRequestIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityIDMappingRequestIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}
func (v UERadioCapabilityIDMappingRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UERadioCapabilityIDMappingRequestIEValue, error) {
	out := UERadioCapabilityIDMappingRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(314):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapabilityID, error) {
			var v struct{ Value s00.UERadioCapabilityID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapabilityID(val_value)
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
		out.rowUERadioCapabilityID = &value
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
func (v UERadioCapabilityIDMappingRequestIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UERadioCapabilityIDMappingRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityIDMappingRequestIEs.id-UERadioCapabilityID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapabilityID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapabilityID }{Value: value}
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
		})(*v.rowUERadioCapabilityID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UERadioCapabilityIDMappingRequestIEValue:", v.id)
	}
}
func BridgeFreshCompletePadding(padding aper.CompletePadding, fresh ...bool) aper.CompletePadding {
	if len(fresh) != 0 && fresh[0] {
		return aper.CompletePadding{}
	}
	return padding
}

type AdditionalGUTIExtIETable struct{}

func AdditionalGUTIExtIEs() AdditionalGUTIExtIETable { return AdditionalGUTIExtIETable{} }

// ID returns the ASN.1 object-set identity of AdditionalGUTIExtIETable.
func (AdditionalGUTIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Additional-GUTI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by AdditionalGUTIExtIETable.
func (AdditionalGUTIExtIETable) Table() s00.AdditionalGUTIExtIEsValueExtensionTable {
	return func() s00.AdditionalGUTIExtIEsValueExtensionTable {
		sealed := s00.AdditionalGUTIExtIEsValueExtensionTable{}
		*s00.BridgeAdditionalGUTIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in AdditionalGUTIExtIETable.
func (t AdditionalGUTIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (AdditionalGUTIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AdditionalGUTIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AdditionalGUTIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AdditionalGUTIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AdditionalGUTIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.AdditionalGUTIExtIEsValue {
			sealed := s03.AdditionalGUTIExtIEsValue{}
			*s03.BridgeAdditionalGUTIExtIEsValueFieldId(&sealed) = id
			*s03.BridgeAdditionalGUTIExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeAdditionalGUTIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type AllocationAndRetentionPriorityExtIETable struct{}

func AllocationAndRetentionPriorityExtIEs() AllocationAndRetentionPriorityExtIETable {
	return AllocationAndRetentionPriorityExtIETable{}
}

// ID returns the ASN.1 object-set identity of AllocationAndRetentionPriorityExtIETable.
func (AllocationAndRetentionPriorityExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AllocationAndRetentionPriority-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by AllocationAndRetentionPriorityExtIETable.
func (AllocationAndRetentionPriorityExtIETable) Table() s00.AllocationAndRetentionPriorityExtIEsValueExtensionTable {
	return func() s00.AllocationAndRetentionPriorityExtIEsValueExtensionTable {
		sealed := s00.AllocationAndRetentionPriorityExtIEsValueExtensionTable{}
		*s00.BridgeAllocationAndRetentionPriorityExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in AllocationAndRetentionPriorityExtIETable.
func (t AllocationAndRetentionPriorityExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (AllocationAndRetentionPriorityExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AllocationAndRetentionPriorityExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AllocationAndRetentionPriorityExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AllocationAndRetentionPriorityExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AllocationAndRetentionPriorityExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.AllocationAndRetentionPriorityExtIEsValue {
			sealed := s03.AllocationAndRetentionPriorityExtIEsValue{}
			*s03.BridgeAllocationAndRetentionPriorityExtIEsValueFieldId(&sealed) = id
			*s03.BridgeAllocationAndRetentionPriorityExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeAllocationAndRetentionPriorityExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type AssistanceDataForPagingExtIETable struct{}

func AssistanceDataForPagingExtIEs() AssistanceDataForPagingExtIETable {
	return AssistanceDataForPagingExtIETable{}
}

// ID returns the ASN.1 object-set identity of AssistanceDataForPagingExtIETable.
func (AssistanceDataForPagingExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AssistanceDataForPaging-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by AssistanceDataForPagingExtIETable.
func (AssistanceDataForPagingExtIETable) Table() s00.AssistanceDataForPagingExtIEsValueExtensionTable {
	return func() s00.AssistanceDataForPagingExtIEsValueExtensionTable {
		sealed := s00.AssistanceDataForPagingExtIEsValueExtensionTable{}
		*s00.BridgeAssistanceDataForPagingExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in AssistanceDataForPagingExtIETable.
func (t AssistanceDataForPagingExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (AssistanceDataForPagingExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceDataForPagingExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AssistanceDataForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceDataForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AssistanceDataForPagingExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.AssistanceDataForPagingExtIEsValue {
			sealed := s03.AssistanceDataForPagingExtIEsValue{}
			*s03.BridgeAssistanceDataForPagingExtIEsValueFieldId(&sealed) = id
			*s03.BridgeAssistanceDataForPagingExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeAssistanceDataForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type AssistanceDataForRecommendedCellsExtIETable struct{}

func AssistanceDataForRecommendedCellsExtIEs() AssistanceDataForRecommendedCellsExtIETable {
	return AssistanceDataForRecommendedCellsExtIETable{}
}

// ID returns the ASN.1 object-set identity of AssistanceDataForRecommendedCellsExtIETable.
func (AssistanceDataForRecommendedCellsExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AssistanceDataForRecommendedCells-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by AssistanceDataForRecommendedCellsExtIETable.
func (AssistanceDataForRecommendedCellsExtIETable) Table() s00.AssistanceDataForRecommendedCellsExtIEsValueExtensionTable {
	return func() s00.AssistanceDataForRecommendedCellsExtIEsValueExtensionTable {
		sealed := s00.AssistanceDataForRecommendedCellsExtIEsValueExtensionTable{}
		*s00.BridgeAssistanceDataForRecommendedCellsExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in AssistanceDataForRecommendedCellsExtIETable.
func (t AssistanceDataForRecommendedCellsExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (AssistanceDataForRecommendedCellsExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceDataForRecommendedCellsExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AssistanceDataForRecommendedCellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceDataForRecommendedCellsExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return AssistanceDataForRecommendedCellsExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.AssistanceDataForRecommendedCellsExtIEsValue {
			sealed := s03.AssistanceDataForRecommendedCellsExtIEsValue{}
			*s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldId(&sealed) = id
			*s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type BearersSubjectToDLDiscardingItemExtIETable struct{}

func BearersSubjectToDLDiscardingItemExtIEs() BearersSubjectToDLDiscardingItemExtIETable {
	return BearersSubjectToDLDiscardingItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToDLDiscardingItemExtIETable.
func (BearersSubjectToDLDiscardingItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscarding-ItemExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToDLDiscardingItemExtIETable.
func (BearersSubjectToDLDiscardingItemExtIETable) Table() s00.BearersSubjectToDLDiscardingItemExtIEsValueExtensionTable {
	return func() s00.BearersSubjectToDLDiscardingItemExtIEsValueExtensionTable {
		sealed := s00.BearersSubjectToDLDiscardingItemExtIEsValueExtensionTable{}
		*s00.BridgeBearersSubjectToDLDiscardingItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToDLDiscardingItemExtIETable.
func (t BearersSubjectToDLDiscardingItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (BearersSubjectToDLDiscardingItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BearersSubjectToDLDiscardingItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BearersSubjectToDLDiscardingItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BearersSubjectToDLDiscardingItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return BearersSubjectToDLDiscardingItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.BearersSubjectToDLDiscardingItemExtIEsValue {
			sealed := s03.BearersSubjectToDLDiscardingItemExtIEsValue{}
			*s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type BearersSubjectToEarlyStatusTransferItemExtIETable struct{}

func BearersSubjectToEarlyStatusTransferItemExtIEs() BearersSubjectToEarlyStatusTransferItemExtIETable {
	return BearersSubjectToEarlyStatusTransferItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToEarlyStatusTransferItemExtIETable.
func (BearersSubjectToEarlyStatusTransferItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToEarlyStatusTransferItemExtIETable.
func (BearersSubjectToEarlyStatusTransferItemExtIETable) Table() s00.BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTable {
	return func() s00.BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTable {
		sealed := s00.BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTable{}
		*s00.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToEarlyStatusTransferItemExtIETable.
func (t BearersSubjectToEarlyStatusTransferItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (BearersSubjectToEarlyStatusTransferItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return BearersSubjectToEarlyStatusTransferItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue {
			sealed := s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue{}
			*s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type BluetoothMeasurementConfigurationExtIETable struct{}

func BluetoothMeasurementConfigurationExtIEs() BluetoothMeasurementConfigurationExtIETable {
	return BluetoothMeasurementConfigurationExtIETable{}
}

// ID returns the ASN.1 object-set identity of BluetoothMeasurementConfigurationExtIETable.
func (BluetoothMeasurementConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BluetoothMeasurementConfiguration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BluetoothMeasurementConfigurationExtIETable.
func (BluetoothMeasurementConfigurationExtIETable) Table() s00.BluetoothMeasurementConfigurationExtIEsValueExtensionTable {
	return func() s00.BluetoothMeasurementConfigurationExtIEsValueExtensionTable {
		sealed := s00.BluetoothMeasurementConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeBluetoothMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BluetoothMeasurementConfigurationExtIETable.
func (t BluetoothMeasurementConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (BluetoothMeasurementConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BluetoothMeasurementConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BluetoothMeasurementConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BluetoothMeasurementConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return BluetoothMeasurementConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.BluetoothMeasurementConfigurationExtIEsValue {
			sealed := s03.BluetoothMeasurementConfigurationExtIEsValue{}
			*s03.BridgeBluetoothMeasurementConfigurationExtIEsValueFieldId(&sealed) = id
			*s03.BridgeBluetoothMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeBluetoothMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CGIExtIETable struct{}

func CGIExtIEs() CGIExtIETable { return CGIExtIETable{} }

// ID returns the ASN.1 object-set identity of CGIExtIETable.
func (CGIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CGI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CGIExtIETable.
func (CGIExtIETable) Table() s00.CGIExtIEsValueExtensionTable {
	return func() s00.CGIExtIEsValueExtensionTable {
		sealed := s00.CGIExtIEsValueExtensionTable{}
		*s00.BridgeCGIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CGIExtIETable.
func (t CGIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CGIExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CGIExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CGIExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CGIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CGIExtIEsValue {
			sealed := s03.CGIExtIEsValue{}
			*s03.BridgeCGIExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCGIExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCGIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CNTypeRestrictionsItemExtIETable struct{}

func CNTypeRestrictionsItemExtIEs() CNTypeRestrictionsItemExtIETable {
	return CNTypeRestrictionsItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CNTypeRestrictionsItemExtIETable.
func (CNTypeRestrictionsItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CNTypeRestrictions-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CNTypeRestrictionsItemExtIETable.
func (CNTypeRestrictionsItemExtIETable) Table() s00.CNTypeRestrictionsItemExtIEsValueExtensionTable {
	return func() s00.CNTypeRestrictionsItemExtIEsValueExtensionTable {
		sealed := s00.CNTypeRestrictionsItemExtIEsValueExtensionTable{}
		*s00.BridgeCNTypeRestrictionsItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CNTypeRestrictionsItemExtIETable.
func (t CNTypeRestrictionsItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CNTypeRestrictionsItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CNTypeRestrictionsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CNTypeRestrictionsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CNTypeRestrictionsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CNTypeRestrictionsItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CNTypeRestrictionsItemExtIEsValue {
			sealed := s03.CNTypeRestrictionsItemExtIEsValue{}
			*s03.BridgeCNTypeRestrictionsItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCNTypeRestrictionsItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCNTypeRestrictionsItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type COUNTValueExtendedExtIETable struct{}

func COUNTValueExtendedExtIEs() COUNTValueExtendedExtIETable { return COUNTValueExtendedExtIETable{} }

// ID returns the ASN.1 object-set identity of COUNTValueExtendedExtIETable.
func (COUNTValueExtendedExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTValueExtended-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by COUNTValueExtendedExtIETable.
func (COUNTValueExtendedExtIETable) Table() s00.COUNTValueExtendedExtIEsValueExtensionTable {
	return func() s00.COUNTValueExtendedExtIEsValueExtensionTable {
		sealed := s00.COUNTValueExtendedExtIEsValueExtensionTable{}
		*s00.BridgeCOUNTValueExtendedExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in COUNTValueExtendedExtIETable.
func (t COUNTValueExtendedExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (COUNTValueExtendedExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return COUNTValueExtendedExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return COUNTValueExtendedExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return COUNTValueExtendedExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return COUNTValueExtendedExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.COUNTValueExtendedExtIEsValue {
			sealed := s03.COUNTValueExtendedExtIEsValue{}
			*s03.BridgeCOUNTValueExtendedExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCOUNTValueExtendedExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCOUNTValueExtendedExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type COUNTvalueExtIETable struct{}

func COUNTvalueExtIEs() COUNTvalueExtIETable { return COUNTvalueExtIETable{} }

// ID returns the ASN.1 object-set identity of COUNTvalueExtIETable.
func (COUNTvalueExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvalue-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by COUNTvalueExtIETable.
func (COUNTvalueExtIETable) Table() s00.COUNTvalueExtIEsValueExtensionTable {
	return func() s00.COUNTvalueExtIEsValueExtensionTable {
		sealed := s00.COUNTvalueExtIEsValueExtensionTable{}
		*s00.BridgeCOUNTvalueExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in COUNTvalueExtIETable.
func (t COUNTvalueExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (COUNTvalueExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return COUNTvalueExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return COUNTvalueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return COUNTvalueExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return COUNTvalueExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.COUNTvalueExtIEsValue {
			sealed := s03.COUNTvalueExtIEsValue{}
			*s03.BridgeCOUNTvalueExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCOUNTvalueExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCOUNTvalueExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type COUNTvaluePDCPSNlength18ExtIETable struct{}

func COUNTvaluePDCPSNlength18ExtIEs() COUNTvaluePDCPSNlength18ExtIETable {
	return COUNTvaluePDCPSNlength18ExtIETable{}
}

// ID returns the ASN.1 object-set identity of COUNTvaluePDCPSNlength18ExtIETable.
func (COUNTvaluePDCPSNlength18ExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvaluePDCP-SNlength18-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by COUNTvaluePDCPSNlength18ExtIETable.
func (COUNTvaluePDCPSNlength18ExtIETable) Table() s00.COUNTvaluePDCPSNlength18ExtIEsValueExtensionTable {
	return func() s00.COUNTvaluePDCPSNlength18ExtIEsValueExtensionTable {
		sealed := s00.COUNTvaluePDCPSNlength18ExtIEsValueExtensionTable{}
		*s00.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in COUNTvaluePDCPSNlength18ExtIETable.
func (t COUNTvaluePDCPSNlength18ExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (COUNTvaluePDCPSNlength18ExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return COUNTvaluePDCPSNlength18ExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return COUNTvaluePDCPSNlength18ExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return COUNTvaluePDCPSNlength18ExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return COUNTvaluePDCPSNlength18ExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.COUNTvaluePDCPSNlength18ExtIEsValue {
			sealed := s03.COUNTvaluePDCPSNlength18ExtIEsValue{}
			*s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CSGIdListItemExtIETable struct{}

func CSGIdListItemExtIEs() CSGIdListItemExtIETable { return CSGIdListItemExtIETable{} }

// ID returns the ASN.1 object-set identity of CSGIdListItemExtIETable.
func (CSGIdListItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-IdList-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CSGIdListItemExtIETable.
func (CSGIdListItemExtIETable) Table() s00.CSGIdListItemExtIEsValueExtensionTable {
	return func() s00.CSGIdListItemExtIEsValueExtensionTable {
		sealed := s00.CSGIdListItemExtIEsValueExtensionTable{}
		*s00.BridgeCSGIdListItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CSGIdListItemExtIETable.
func (t CSGIdListItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CSGIdListItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CSGIdListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CSGIdListItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CSGIdListItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CSGIdListItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CSGIdListItemExtIEsValue {
			sealed := s03.CSGIdListItemExtIEsValue{}
			*s03.BridgeCSGIdListItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCSGIdListItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCSGIdListItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CancelledCellinEAIItemExtIETable struct{}

func CancelledCellinEAIItemExtIEs() CancelledCellinEAIItemExtIETable {
	return CancelledCellinEAIItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CancelledCellinEAIItemExtIETable.
func (CancelledCellinEAIItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CancelledCellinEAI-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CancelledCellinEAIItemExtIETable.
func (CancelledCellinEAIItemExtIETable) Table() s00.CancelledCellinEAIItemExtIEsValueExtensionTable {
	return func() s00.CancelledCellinEAIItemExtIEsValueExtensionTable {
		sealed := s00.CancelledCellinEAIItemExtIEsValueExtensionTable{}
		*s00.BridgeCancelledCellinEAIItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CancelledCellinEAIItemExtIETable.
func (t CancelledCellinEAIItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CancelledCellinEAIItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CancelledCellinEAIItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CancelledCellinEAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CancelledCellinEAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CancelledCellinEAIItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CancelledCellinEAIItemExtIEsValue {
			sealed := s03.CancelledCellinEAIItemExtIEsValue{}
			*s03.BridgeCancelledCellinEAIItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCancelledCellinEAIItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCancelledCellinEAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CancelledCellinTAIItemExtIETable struct{}

func CancelledCellinTAIItemExtIEs() CancelledCellinTAIItemExtIETable {
	return CancelledCellinTAIItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of CancelledCellinTAIItemExtIETable.
func (CancelledCellinTAIItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CancelledCellinTAI-Item-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CancelledCellinTAIItemExtIETable.
func (CancelledCellinTAIItemExtIETable) Table() s00.CancelledCellinTAIItemExtIEsValueExtensionTable {
	return func() s00.CancelledCellinTAIItemExtIEsValueExtensionTable {
		sealed := s00.CancelledCellinTAIItemExtIEsValueExtensionTable{}
		*s00.BridgeCancelledCellinTAIItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CancelledCellinTAIItemExtIETable.
func (t CancelledCellinTAIItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CancelledCellinTAIItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CancelledCellinTAIItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CancelledCellinTAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CancelledCellinTAIItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CancelledCellinTAIItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CancelledCellinTAIItemExtIEsValue {
			sealed := s03.CancelledCellinTAIItemExtIEsValue{}
			*s03.BridgeCancelledCellinTAIItemExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCancelledCellinTAIItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCancelledCellinTAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type Cdma2000OneXSRVCCInfoExtIETable struct{}

func Cdma2000OneXSRVCCInfoExtIEs() Cdma2000OneXSRVCCInfoExtIETable {
	return Cdma2000OneXSRVCCInfoExtIETable{}
}

// ID returns the ASN.1 object-set identity of Cdma2000OneXSRVCCInfoExtIETable.
func (Cdma2000OneXSRVCCInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000OneXSRVCCInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by Cdma2000OneXSRVCCInfoExtIETable.
func (Cdma2000OneXSRVCCInfoExtIETable) Table() s00.Cdma2000OneXSRVCCInfoExtIEsValueExtensionTable {
	return func() s00.Cdma2000OneXSRVCCInfoExtIEsValueExtensionTable {
		sealed := s00.Cdma2000OneXSRVCCInfoExtIEsValueExtensionTable{}
		*s00.BridgeCdma2000OneXSRVCCInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in Cdma2000OneXSRVCCInfoExtIETable.
func (t Cdma2000OneXSRVCCInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (Cdma2000OneXSRVCCInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return Cdma2000OneXSRVCCInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return Cdma2000OneXSRVCCInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return Cdma2000OneXSRVCCInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return Cdma2000OneXSRVCCInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.Cdma2000OneXSRVCCInfoExtIEsValue {
			sealed := s03.Cdma2000OneXSRVCCInfoExtIEsValue{}
			*s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CellBasedMDTExtIETable struct{}

func CellBasedMDTExtIEs() CellBasedMDTExtIETable { return CellBasedMDTExtIETable{} }

// ID returns the ASN.1 object-set identity of CellBasedMDTExtIETable.
func (CellBasedMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellBasedMDT-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CellBasedMDTExtIETable.
func (CellBasedMDTExtIETable) Table() s00.CellBasedMDTExtIEsValueExtensionTable {
	return func() s00.CellBasedMDTExtIEsValueExtensionTable {
		sealed := s00.CellBasedMDTExtIEsValueExtensionTable{}
		*s00.BridgeCellBasedMDTExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CellBasedMDTExtIETable.
func (t CellBasedMDTExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CellBasedMDTExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CellBasedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CellBasedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CellBasedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CellBasedMDTExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CellBasedMDTExtIEsValue {
			sealed := s03.CellBasedMDTExtIEsValue{}
			*s03.BridgeCellBasedMDTExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCellBasedMDTExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCellBasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CellBasedQMCExtIETable struct{}

func CellBasedQMCExtIEs() CellBasedQMCExtIETable { return CellBasedQMCExtIETable{} }

// ID returns the ASN.1 object-set identity of CellBasedQMCExtIETable.
func (CellBasedQMCExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellBasedQMC-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CellBasedQMCExtIETable.
func (CellBasedQMCExtIETable) Table() s00.CellBasedQMCExtIEsValueExtensionTable {
	return func() s00.CellBasedQMCExtIEsValueExtensionTable {
		sealed := s00.CellBasedQMCExtIEsValueExtensionTable{}
		*s00.BridgeCellBasedQMCExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CellBasedQMCExtIETable.
func (t CellBasedQMCExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CellBasedQMCExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CellBasedQMCExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CellBasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CellBasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CellBasedQMCExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CellBasedQMCExtIEsValue {
			sealed := s03.CellBasedQMCExtIEsValue{}
			*s03.BridgeCellBasedQMCExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCellBasedQMCExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCellBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type CSGMembershipInfoExtIETable struct{}

func CSGMembershipInfoExtIEs() CSGMembershipInfoExtIETable { return CSGMembershipInfoExtIETable{} }

// ID returns the ASN.1 object-set identity of CSGMembershipInfoExtIETable.
func (CSGMembershipInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "CSGMembershipInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by CSGMembershipInfoExtIETable.
func (CSGMembershipInfoExtIETable) Table() s00.CSGMembershipInfoExtIEsValueExtensionTable {
	return func() s00.CSGMembershipInfoExtIEsValueExtensionTable {
		sealed := s00.CSGMembershipInfoExtIEsValueExtensionTable{}
		*s00.BridgeCSGMembershipInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in CSGMembershipInfoExtIETable.
func (t CSGMembershipInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (CSGMembershipInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return CSGMembershipInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return CSGMembershipInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return CSGMembershipInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return CSGMembershipInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s03.CSGMembershipInfoExtIEsValue {
			sealed := s03.CSGMembershipInfoExtIEsValue{}
			*s03.BridgeCSGMembershipInfoExtIEsValueFieldId(&sealed) = id
			*s03.BridgeCSGMembershipInfoExtIEsValueFieldOpaque(&sealed) = opaque
			*s03.BridgeCSGMembershipInfoExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// BitRateCodec binds the complete source value type.
func BitRateCodec() s00.BitRateValueCodec {
	return func() s00.BitRateValueCodec {
		sealed := s00.BitRateValueCodec{}
		*s00.BridgeBitRateValueCodecFieldPath(&sealed) = "BitRate"
		*s00.BridgeBitRateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BitRate, error) {
			var zero s00.BitRate
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.BitRate, error) {
				var v struct{ Value s00.BitRate }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, BridgeInt64Ptr(0), BridgeInt64Ptr(10000000000), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.BitRate(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "BitRate"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeBitRateValueCodecFieldEncode(&sealed) = func(value s00.BitRate, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.BitRate, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.BitRate }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), BridgeInt64Ptr(0), BridgeInt64Ptr(10000000000), false); err != nil {
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
		*s00.BridgeBitRateValueCodecFieldCapture(&sealed) = func(v s00.BitRate, options aper.DecodeState) (s00.BitRate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APBitRate(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeBitRateValueCodecFieldCompare(&sealed) = func(v s00.BitRate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APBitRate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeBitRateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BitRate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RACCodec binds the complete source value type.
func RACCodec() s01.RACValueCodec {
	return func() s01.RACValueCodec {
		sealed := s01.RACValueCodec{}
		*s01.BridgeRACValueCodecFieldPath(&sealed) = "RAC"
		*s01.BridgeRACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RAC, error) {
			var zero s00.RAC
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.RAC, error) {
				var v struct{ Value s00.RAC }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.RAC(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "RAC"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeRACValueCodecFieldEncode(&sealed) = func(value s00.RAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.RAC, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.RAC }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 1, 1, true); err != nil {
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
		*s01.BridgeRACValueCodecFieldCapture(&sealed) = func(v s00.RAC, options aper.DecodeState) (s00.RAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRAC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s01.BridgeRACValueCodecFieldCompare(&sealed) = func(v s00.RAC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APRAC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RAC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RIMInformationCodec binds the complete source value type.
func RIMInformationCodec() s01.RIMInformationValueCodec {
	return func() s01.RIMInformationValueCodec {
		sealed := s01.RIMInformationValueCodec{}
		*s01.BridgeRIMInformationValueCodecFieldPath(&sealed) = "RIMInformation"
		*s01.BridgeRIMInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RIMInformation, error) {
			var zero s00.RIMInformation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.RIMInformation, error) {
				var v struct{ Value s00.RIMInformation }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.RIMInformation(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "RIMInformation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeRIMInformationValueCodecFieldEncode(&sealed) = func(value s00.RIMInformation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.RIMInformation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.RIMInformation }{Value: value}
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
			})(value, budget)
		}
		*s01.BridgeRIMInformationValueCodecFieldCapture(&sealed) = func(v s00.RIMInformation, options aper.DecodeState) (s00.RIMInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRIMInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRIMInformationValueCodecFieldCompare(&sealed) = func(v s00.RIMInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APRIMInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRIMInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RIMInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RRCContainerCodec binds the complete source value type.
func RRCContainerCodec() s01.RRCContainerValueCodec {
	return func() s01.RRCContainerValueCodec {
		sealed := s01.RRCContainerValueCodec{}
		*s01.BridgeRRCContainerValueCodecFieldPath(&sealed) = "RRCContainer"
		*s01.BridgeRRCContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RRCContainer, error) {
			var zero s00.RRCContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.RRCContainer, error) {
				var v struct{ Value s00.RRCContainer }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.RRCContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "RRCContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeRRCContainerValueCodecFieldEncode(&sealed) = func(value s00.RRCContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.RRCContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.RRCContainer }{Value: value}
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
			})(value, budget)
		}
		*s01.BridgeRRCContainerValueCodecFieldCapture(&sealed) = func(v s00.RRCContainer, options aper.DecodeState) (s00.RRCContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRRCContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRRCContainerValueCodecFieldCompare(&sealed) = func(v s00.RRCContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APRRCContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeRRCContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RRCContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RangeCodec binds the complete source value type.
func RangeCodec() s01.RangeValueCodec {
	return func() s01.RangeValueCodec {
		sealed := s01.RangeValueCodec{}
		*s01.BridgeRangeValueCodecFieldPath(&sealed) = "Range"
		*s01.BridgeRangeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Range, error) {
			var zero s00.Range
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.Range, error) {
				var v struct{ Value s00.Range }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 9, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.Range(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Range"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeRangeValueCodecFieldEncode(&sealed) = func(value s00.Range, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.Range, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.Range }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 9, true); err != nil {
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
		*s01.BridgeRangeValueCodecFieldCapture(&sealed) = func(v s00.Range, options aper.DecodeState) (s00.Range, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRange(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s01.BridgeRangeValueCodecFieldCompare(&sealed) = func(v s00.Range, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APRange(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRangeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Range"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ReceiveStatusofULPDCPSDUsCodec binds the complete source value type.
func ReceiveStatusofULPDCPSDUsCodec() s01.ReceiveStatusofULPDCPSDUsValueCodec {
	return func() s01.ReceiveStatusofULPDCPSDUsValueCodec {
		sealed := s01.ReceiveStatusofULPDCPSDUsValueCodec{}
		*s01.BridgeReceiveStatusofULPDCPSDUsValueCodecFieldPath(&sealed) = "ReceiveStatusofULPDCPSDUs"
		*s01.BridgeReceiveStatusofULPDCPSDUsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReceiveStatusofULPDCPSDUs, error) {
			var zero s00.ReceiveStatusofULPDCPSDUs
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ReceiveStatusofULPDCPSDUs, error) {
				var v struct{ Value s00.ReceiveStatusofULPDCPSDUs }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 4096, 4096, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ReceiveStatusofULPDCPSDUs"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeReceiveStatusofULPDCPSDUsValueCodecFieldEncode(&sealed) = func(value s00.ReceiveStatusofULPDCPSDUs, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ReceiveStatusofULPDCPSDUs, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ReceiveStatusofULPDCPSDUs }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 4096, 4096, true); err != nil {
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
		*s01.BridgeReceiveStatusofULPDCPSDUsValueCodecFieldCapture(&sealed) = func(v s00.ReceiveStatusofULPDCPSDUs, options aper.DecodeState) (s00.ReceiveStatusofULPDCPSDUs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APReceiveStatusofULPDCPSDUs(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeReceiveStatusofULPDCPSDUsValueCodecFieldCompare(&sealed) = func(v s00.ReceiveStatusofULPDCPSDUs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APReceiveStatusofULPDCPSDUs(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeReceiveStatusofULPDCPSDUsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReceiveStatusofULPDCPSDUs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ReportAmountMDTCodec binds the complete source value type.
func ReportAmountMDTCodec() s02.ReportAmountMDTValueCodec {
	return func() s02.ReportAmountMDTValueCodec {
		sealed := s02.ReportAmountMDTValueCodec{}
		*s02.BridgeReportAmountMDTValueCodecFieldPath(&sealed) = "ReportAmountMDT"
		*s02.BridgeReportAmountMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReportAmountMDT, error) {
			var zero s00.ReportAmountMDT
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ReportAmountMDT, error) {
				var v struct{ Value s00.ReportAmountMDT }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 8, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ReportAmountMDT(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ReportAmountMDT"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeReportAmountMDTValueCodecFieldEncode(&sealed) = func(value s00.ReportAmountMDT, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ReportAmountMDT, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ReportAmountMDT }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 8, false); err != nil {
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
		*s02.BridgeReportAmountMDTValueCodecFieldCapture(&sealed) = func(v s00.ReportAmountMDT, options aper.DecodeState) (s00.ReportAmountMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APReportAmountMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeReportAmountMDTValueCodecFieldCompare(&sealed) = func(v s00.ReportAmountMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APReportAmountMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeReportAmountMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReportAmountMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ReportAreaCodec binds the complete source value type.
func ReportAreaCodec() s02.ReportAreaValueCodec {
	return func() s02.ReportAreaValueCodec {
		sealed := s02.ReportAreaValueCodec{}
		*s02.BridgeReportAreaValueCodecFieldPath(&sealed) = "ReportArea"
		*s02.BridgeReportAreaValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReportArea, error) {
			var zero s00.ReportArea
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ReportArea, error) {
				var v struct{ Value s00.ReportArea }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ReportArea(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ReportArea"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeReportAreaValueCodecFieldEncode(&sealed) = func(value s00.ReportArea, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ReportArea, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ReportArea }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
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
		*s02.BridgeReportAreaValueCodecFieldCapture(&sealed) = func(v s00.ReportArea, options aper.DecodeState) (s00.ReportArea, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APReportArea(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeReportAreaValueCodecFieldCompare(&sealed) = func(v s00.ReportArea, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APReportArea(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeReportAreaValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReportArea"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ReportIntervalMDTCodec binds the complete source value type.
func ReportIntervalMDTCodec() s02.ReportIntervalMDTValueCodec {
	return func() s02.ReportIntervalMDTValueCodec {
		sealed := s02.ReportIntervalMDTValueCodec{}
		*s02.BridgeReportIntervalMDTValueCodecFieldPath(&sealed) = "ReportIntervalMDT"
		*s02.BridgeReportIntervalMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReportIntervalMDT, error) {
			var zero s00.ReportIntervalMDT
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ReportIntervalMDT, error) {
				var v struct{ Value s00.ReportIntervalMDT }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 13, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ReportIntervalMDT(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ReportIntervalMDT"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeReportIntervalMDTValueCodecFieldEncode(&sealed) = func(value s00.ReportIntervalMDT, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ReportIntervalMDT, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ReportIntervalMDT }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 13, false); err != nil {
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
		*s02.BridgeReportIntervalMDTValueCodecFieldCapture(&sealed) = func(v s00.ReportIntervalMDT, options aper.DecodeState) (s00.ReportIntervalMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APReportIntervalMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s02.BridgeReportIntervalMDTValueCodecFieldCompare(&sealed) = func(v s00.ReportIntervalMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APReportIntervalMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeReportIntervalMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReportIntervalMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ResetAllCodec binds the complete source value type.
func ResetAllCodec() s02.ResetAllValueCodec {
	return func() s02.ResetAllValueCodec {
		sealed := s02.ResetAllValueCodec{}
		*s02.BridgeResetAllValueCodecFieldPath(&sealed) = "ResetAll"
		*s02.BridgeResetAllValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ResetAll, error) {
			var zero s00.ResetAll
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ResetAll, error) {
				var v struct{ Value s00.ResetAll }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ResetAll(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ResetAll"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeResetAllValueCodecFieldEncode(&sealed) = func(value s00.ResetAll, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ResetAll, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ResetAll }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
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
		*s02.BridgeResetAllValueCodecFieldCapture(&sealed) = func(v s00.ResetAll, options aper.DecodeState) (s00.ResetAll, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APResetAll(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeResetAllValueCodecFieldCompare(&sealed) = func(v s00.ResetAll, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APResetAll(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeResetAllValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResetAll"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SONInformationRequestCodec binds the complete source value type.
func SONInformationRequestCodec() s02.SONInformationRequestValueCodec {
	return func() s02.SONInformationRequestValueCodec {
		sealed := s02.SONInformationRequestValueCodec{}
		*s02.BridgeSONInformationRequestValueCodecFieldPath(&sealed) = "SONInformationRequest"
		*s02.BridgeSONInformationRequestValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SONInformationRequest, error) {
			var zero s00.SONInformationRequest
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SONInformationRequest, error) {
				var v struct{ Value s00.SONInformationRequest }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 3, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SONInformationRequest(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SONInformationRequest"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSONInformationRequestValueCodecFieldEncode(&sealed) = func(value s00.SONInformationRequest, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SONInformationRequest, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.SONInformationRequest }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
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
		*s02.BridgeSONInformationRequestValueCodecFieldCapture(&sealed) = func(v s00.SONInformationRequest, options aper.DecodeState) (s00.SONInformationRequest, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSONInformationRequest(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s02.BridgeSONInformationRequestValueCodecFieldCompare(&sealed) = func(v s00.SONInformationRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSONInformationRequest(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSONInformationRequestValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONInformationRequest"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SONtransferApplicationIdentityCodec binds the complete source value type.
func SONtransferApplicationIdentityCodec() s02.SONtransferApplicationIdentityValueCodec {
	return func() s02.SONtransferApplicationIdentityValueCodec {
		sealed := s02.SONtransferApplicationIdentityValueCodec{}
		*s02.BridgeSONtransferApplicationIdentityValueCodecFieldPath(&sealed) = "SONtransferApplicationIdentity"
		*s02.BridgeSONtransferApplicationIdentityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SONtransferApplicationIdentity, error) {
			var zero s00.SONtransferApplicationIdentity
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SONtransferApplicationIdentity, error) {
				var v struct {
					Value s00.SONtransferApplicationIdentity
				}
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 6, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SONtransferApplicationIdentity(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SONtransferApplicationIdentity"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSONtransferApplicationIdentityValueCodecFieldEncode(&sealed) = func(value s00.SONtransferApplicationIdentity, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SONtransferApplicationIdentity, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.SONtransferApplicationIdentity
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
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
		*s02.BridgeSONtransferApplicationIdentityValueCodecFieldCapture(&sealed) = func(v s00.SONtransferApplicationIdentity, options aper.DecodeState) (s00.SONtransferApplicationIdentity, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSONtransferApplicationIdentity(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSONtransferApplicationIdentityValueCodecFieldCompare(&sealed) = func(v s00.SONtransferApplicationIdentity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompareS1APSONtransferApplicationIdentity(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSONtransferApplicationIdentityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONtransferApplicationIdentity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SecondaryRATTypeCodec binds the complete source value type.
func SecondaryRATTypeCodec() s02.SecondaryRATTypeValueCodec {
	return func() s02.SecondaryRATTypeValueCodec {
		sealed := s02.SecondaryRATTypeValueCodec{}
		*s02.BridgeSecondaryRATTypeValueCodecFieldPath(&sealed) = "SecondaryRATType"
		*s02.BridgeSecondaryRATTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SecondaryRATType, error) {
			var zero s00.SecondaryRATType
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SecondaryRATType, error) {
				var v struct{ Value s00.SecondaryRATType }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SecondaryRATType(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SecondaryRATType"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSecondaryRATTypeValueCodecFieldEncode(&sealed) = func(value s00.SecondaryRATType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SecondaryRATType, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.SecondaryRATType }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
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
		*s02.BridgeSecondaryRATTypeValueCodecFieldCapture(&sealed) = func(v s00.SecondaryRATType, options aper.DecodeState) (s00.SecondaryRATType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APSecondaryRATType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSecondaryRATTypeValueCodecFieldCompare(&sealed) = func(v s00.SecondaryRATType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecondaryRATType(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeSecondaryRATTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SensorMeasConfigCodec binds the complete source value type.
func SensorMeasConfigCodec() s02.SensorMeasConfigValueCodec {
	return func() s02.SensorMeasConfigValueCodec {
		sealed := s02.SensorMeasConfigValueCodec{}
		*s02.BridgeSensorMeasConfigValueCodecFieldPath(&sealed) = "SensorMeasConfig"
		*s02.BridgeSensorMeasConfigValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SensorMeasConfig, error) {
			var zero s00.SensorMeasConfig
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SensorMeasConfig, error) {
				var v struct{ Value s00.SensorMeasConfig }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SensorMeasConfig(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SensorMeasConfig"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSensorMeasConfigValueCodecFieldEncode(&sealed) = func(value s00.SensorMeasConfig, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SensorMeasConfig, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.SensorMeasConfig }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
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
		*s02.BridgeSensorMeasConfigValueCodecFieldCapture(&sealed) = func(v s00.SensorMeasConfig, options aper.DecodeState) (s00.SensorMeasConfig, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APSensorMeasConfig(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSensorMeasConfigValueCodecFieldCompare(&sealed) = func(v s00.SensorMeasConfig, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSensorMeasConfig(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeSensorMeasConfigValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SensorMeasConfig"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SonTransferIEsMobilityInformationCodec binds the complete source value type.
func SonTransferIEsMobilityInformationCodec() s02.SonTransferIEsMobilityInformationValueCodec {
	return func() s02.SonTransferIEsMobilityInformationValueCodec {
		sealed := s02.SonTransferIEsMobilityInformationValueCodec{}
		*s02.BridgeSonTransferIEsMobilityInformationValueCodecFieldPath(&sealed) = "SonTransferIEsMobilityInformation"
		*s02.BridgeSonTransferIEsMobilityInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SonTransferIEsMobilityInformation, error) {
			var zero s00.SonTransferIEsMobilityInformation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SonTransferIEsMobilityInformation, error) {
				var v struct {
					Value s00.SonTransferIEsMobilityInformation
				}
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 32, 32, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SonTransferIEsMobilityInformation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSonTransferIEsMobilityInformationValueCodecFieldEncode(&sealed) = func(value s00.SonTransferIEsMobilityInformation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SonTransferIEsMobilityInformation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.SonTransferIEsMobilityInformation
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 32, 32, true); err != nil {
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
		*s02.BridgeSonTransferIEsMobilityInformationValueCodecFieldCapture(&sealed) = func(v s00.SonTransferIEsMobilityInformation, options aper.DecodeState) (s00.SonTransferIEsMobilityInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSonTransferIEsMobilityInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSonTransferIEsMobilityInformationValueCodecFieldCompare(&sealed) = func(v s00.SonTransferIEsMobilityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSonTransferIEsMobilityInformation(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSonTransferIEsMobilityInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SonTransferIEsMobilityInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceBSSToTargetBSSTransparentContainerCodec binds the complete source value type.
func SourceBSSToTargetBSSTransparentContainerCodec() s02.SourceBSSToTargetBSSTransparentContainerValueCodec {
	return func() s02.SourceBSSToTargetBSSTransparentContainerValueCodec {
		sealed := s02.SourceBSSToTargetBSSTransparentContainerValueCodec{}
		*s02.BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldPath(&sealed) = "SourceBSSToTargetBSSTransparentContainer"
		*s02.BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceBSSToTargetBSSTransparentContainer, error) {
			var zero s00.SourceBSSToTargetBSSTransparentContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SourceBSSToTargetBSSTransparentContainer, error) {
				var v struct {
					Value s00.SourceBSSToTargetBSSTransparentContainer
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SourceBSSToTargetBSSTransparentContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceBSSToTargetBSSTransparentContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceBSSToTargetBSSTransparentContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SourceBSSToTargetBSSTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.SourceBSSToTargetBSSTransparentContainer
				}{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.SourceBSSToTargetBSSTransparentContainer, options aper.DecodeState) (s00.SourceBSSToTargetBSSTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSourceBSSToTargetBSSTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.SourceBSSToTargetBSSTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APSourceBSSToTargetBSSTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s02.BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceBSSToTargetBSSTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceNgRanNodeToTargetNgRanNodeTransparentContainerCodec binds the complete source value type.
func SourceNgRanNodeToTargetNgRanNodeTransparentContainerCodec() s02.SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec {
	return func() s02.SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec {
		sealed := s02.SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec{}
		*s02.BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldPath(&sealed) = "SourceNgRanNodeToTargetNgRanNodeTransparentContainer"
		*s02.BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, error) {
			var zero s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, error) {
				var v struct {
					Value s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceNgRanNodeToTargetNgRanNodeTransparentContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer
				}{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, options aper.DecodeState) (s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSourceNgRanNodeToTargetNgRanNodeTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, root aper.Snapshot,

			budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSourceNgRanNodeToTargetNgRanNodeTransparentContainer(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceNgRanNodeToTargetNgRanNodeTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceOfUEActivityBehaviourInformationCodec binds the complete source value type.
func SourceOfUEActivityBehaviourInformationCodec() s02.SourceOfUEActivityBehaviourInformationValueCodec {
	return func() s02.SourceOfUEActivityBehaviourInformationValueCodec {
		sealed := s02.SourceOfUEActivityBehaviourInformationValueCodec{}
		*s02.BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldPath(&sealed) = "SourceOfUEActivityBehaviourInformation"
		*s02.BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceOfUEActivityBehaviourInformation, error) {
			var zero s00.SourceOfUEActivityBehaviourInformation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SourceOfUEActivityBehaviourInformation, error) {
				var v struct {
					Value s00.SourceOfUEActivityBehaviourInformation
				}
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SourceOfUEActivityBehaviourInformation(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceOfUEActivityBehaviourInformation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldEncode(&sealed) = func(value s00.SourceOfUEActivityBehaviourInformation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SourceOfUEActivityBehaviourInformation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.SourceOfUEActivityBehaviourInformation
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
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
		*s02.BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldCapture(&sealed) = func(v s00.SourceOfUEActivityBehaviourInformation, options aper.DecodeState) (s00.SourceOfUEActivityBehaviourInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSourceOfUEActivityBehaviourInformation(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldCompare(&sealed) = func(v s00.SourceOfUEActivityBehaviourInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSourceOfUEActivityBehaviourInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceOfUEActivityBehaviourInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SourceRNCToTargetRNCTransparentContainerCodec binds the complete source value type.
func SourceRNCToTargetRNCTransparentContainerCodec() s02.SourceRNCToTargetRNCTransparentContainerValueCodec {
	return func() s02.SourceRNCToTargetRNCTransparentContainerValueCodec {
		sealed := s02.SourceRNCToTargetRNCTransparentContainerValueCodec{}
		*s02.BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldPath(&sealed) = "SourceRNCToTargetRNCTransparentContainer"
		*s02.BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceRNCToTargetRNCTransparentContainer, error) {
			var zero s00.SourceRNCToTargetRNCTransparentContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SourceRNCToTargetRNCTransparentContainer, error) {
				var v struct {
					Value s00.SourceRNCToTargetRNCTransparentContainer
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SourceRNCToTargetRNCTransparentContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SourceRNCToTargetRNCTransparentContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceRNCToTargetRNCTransparentContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SourceRNCToTargetRNCTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.SourceRNCToTargetRNCTransparentContainer
				}{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.SourceRNCToTargetRNCTransparentContainer, options aper.DecodeState) (s00.SourceRNCToTargetRNCTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSourceRNCToTargetRNCTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.SourceRNCToTargetRNCTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APSourceRNCToTargetRNCTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s02.BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceRNCToTargetRNCTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// StratumLevelCodec binds the complete source value type.
func StratumLevelCodec() s02.StratumLevelValueCodec {
	return func() s02.StratumLevelValueCodec {
		sealed := s02.StratumLevelValueCodec{}
		*s02.BridgeStratumLevelValueCodecFieldPath(&sealed) = "StratumLevel"
		*s02.BridgeStratumLevelValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.StratumLevel, error) {
			var zero s00.StratumLevel
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.StratumLevel, error) {
				var v struct{ Value s00.StratumLevel }
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "StratumLevel"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeStratumLevelValueCodecFieldEncode(&sealed) = func(value s00.StratumLevel, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.StratumLevel, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.StratumLevel }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true); err != nil {
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
		*s02.BridgeStratumLevelValueCodecFieldCapture(&sealed) = func(v s00.StratumLevel, options aper.DecodeState) (s00.StratumLevel, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APStratumLevel(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeStratumLevelValueCodecFieldCompare(&sealed) = func(v s00.StratumLevel, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APStratumLevel(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s02.BridgeStratumLevelValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:StratumLevel"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SynchronisationStatusCodec binds the complete source value type.
func SynchronisationStatusCodec() s02.SynchronisationStatusValueCodec {
	return func() s02.SynchronisationStatusValueCodec {
		sealed := s02.SynchronisationStatusValueCodec{}
		*s02.BridgeSynchronisationStatusValueCodecFieldPath(&sealed) = "SynchronisationStatus"
		*s02.BridgeSynchronisationStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SynchronisationStatus, error) {
			var zero s00.SynchronisationStatus
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.SynchronisationStatus, error) {
				var v struct{ Value s00.SynchronisationStatus }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.SynchronisationStatus(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "SynchronisationStatus"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeSynchronisationStatusValueCodecFieldEncode(&sealed) = func(value s00.SynchronisationStatus, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.SynchronisationStatus, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.SynchronisationStatus }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
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
		*s02.BridgeSynchronisationStatusValueCodecFieldCapture(&sealed) = func(v s00.SynchronisationStatus, options aper.DecodeState) (s00.SynchronisationStatus, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSynchronisationStatus(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s02.BridgeSynchronisationStatusValueCodecFieldCompare(&sealed) = func(v s00.SynchronisationStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSynchronisationStatus(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSynchronisationStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SynchronisationStatus"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TACCodec binds the complete source value type.
func TACCodec() s02.TACValueCodec {
	return func() s02.TACValueCodec {
		sealed := s02.TACValueCodec{}
		*s02.BridgeTACValueCodecFieldPath(&sealed) = "TAC"
		*s02.BridgeTACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TAC, error) {
			var zero s00.TAC
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TAC, error) {
				var v struct{ Value s00.TAC }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TAC(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TAC"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTACValueCodecFieldEncode(&sealed) = func(value s00.TAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TAC, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.TAC }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 2, 2, true); err != nil {
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
		*s02.BridgeTACValueCodecFieldCapture(&sealed) = func(v s00.TAC, options aper.DecodeState) (s00.TAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTAC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s02.BridgeTACValueCodecFieldCompare(&sealed) = func(v s00.TAC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTAC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TBCDSTRINGCodec binds the complete source value type.
func TBCDSTRINGCodec() s02.TBCDSTRINGValueCodec {
	return func() s02.TBCDSTRINGValueCodec {
		sealed := s02.TBCDSTRINGValueCodec{}
		*s02.BridgeTBCDSTRINGValueCodecFieldPath(&sealed) = "TBCDSTRING"
		*s02.BridgeTBCDSTRINGValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TBCDSTRING, error) {
			var zero s00.TBCDSTRING
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TBCDSTRING, error) {
				var v struct{ Value s00.TBCDSTRING }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TBCDSTRING(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TBCDSTRING"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTBCDSTRINGValueCodecFieldEncode(&sealed) = func(value s00.TBCDSTRING, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TBCDSTRING, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.TBCDSTRING }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 3, 3, true); err != nil {
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
		*s02.BridgeTBCDSTRINGValueCodecFieldCapture(&sealed) = func(v s00.TBCDSTRING, options aper.DecodeState) (s00.TBCDSTRING, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APTBCDSTRING(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTBCDSTRINGValueCodecFieldCompare(&sealed) = func(v s00.TBCDSTRING, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTBCDSTRING(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTBCDSTRINGValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TBCDSTRING"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TargetBSSToSourceBSSTransparentContainerCodec binds the complete source value type.
func TargetBSSToSourceBSSTransparentContainerCodec() s02.TargetBSSToSourceBSSTransparentContainerValueCodec {
	return func() s02.TargetBSSToSourceBSSTransparentContainerValueCodec {
		sealed := s02.TargetBSSToSourceBSSTransparentContainerValueCodec{}
		*s02.BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldPath(&sealed) = "TargetBSSToSourceBSSTransparentContainer"
		*s02.BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TargetBSSToSourceBSSTransparentContainer, error) {
			var zero s00.TargetBSSToSourceBSSTransparentContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TargetBSSToSourceBSSTransparentContainer, error) {
				var v struct {
					Value s00.TargetBSSToSourceBSSTransparentContainer
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TargetBSSToSourceBSSTransparentContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TargetBSSToSourceBSSTransparentContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.TargetBSSToSourceBSSTransparentContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TargetBSSToSourceBSSTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.TargetBSSToSourceBSSTransparentContainer
				}{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.TargetBSSToSourceBSSTransparentContainer, options aper.DecodeState) (s00.TargetBSSToSourceBSSTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTargetBSSToSourceBSSTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.TargetBSSToSourceBSSTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APTargetBSSToSourceBSSTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s02.BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetBSSToSourceBSSTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TargetNgRanNodeToSourceNgRanNodeTransparentContainerCodec binds the complete source value type.
func TargetNgRanNodeToSourceNgRanNodeTransparentContainerCodec() s02.TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec {
	return func() s02.TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec {
		sealed := s02.TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec{}
		*s02.BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldPath(&sealed) = "TargetNgRanNodeToSourceNgRanNodeTransparentContainer"
		*s02.BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, error) {
			var zero s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, error) {
				var v struct {
					Value s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TargetNgRanNodeToSourceNgRanNodeTransparentContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer
				}{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, options aper.DecodeState) (s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTargetNgRanNodeToSourceNgRanNodeTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, root aper.Snapshot,

			budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTargetNgRanNodeToSourceNgRanNodeTransparentContainer(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetNgRanNodeToSourceNgRanNodeTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TargetRNCToSourceRNCTransparentContainerCodec binds the complete source value type.
func TargetRNCToSourceRNCTransparentContainerCodec() s02.TargetRNCToSourceRNCTransparentContainerValueCodec {
	return func() s02.TargetRNCToSourceRNCTransparentContainerValueCodec {
		sealed := s02.TargetRNCToSourceRNCTransparentContainerValueCodec{}
		*s02.BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldPath(&sealed) = "TargetRNCToSourceRNCTransparentContainer"
		*s02.BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TargetRNCToSourceRNCTransparentContainer, error) {
			var zero s00.TargetRNCToSourceRNCTransparentContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TargetRNCToSourceRNCTransparentContainer, error) {
				var v struct {
					Value s00.TargetRNCToSourceRNCTransparentContainer
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TargetRNCToSourceRNCTransparentContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TargetRNCToSourceRNCTransparentContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.TargetRNCToSourceRNCTransparentContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TargetRNCToSourceRNCTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.TargetRNCToSourceRNCTransparentContainer
				}{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.TargetRNCToSourceRNCTransparentContainer, options aper.DecodeState) (s00.TargetRNCToSourceRNCTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTargetRNCToSourceRNCTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.TargetRNCToSourceRNCTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APTargetRNCToSourceRNCTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s02.BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetRNCToSourceRNCTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TimeToTriggerCodec binds the complete source value type.
func TimeToTriggerCodec() s02.TimeToTriggerValueCodec {
	return func() s02.TimeToTriggerValueCodec {
		sealed := s02.TimeToTriggerValueCodec{}
		*s02.BridgeTimeToTriggerValueCodecFieldPath(&sealed) = "TimeToTrigger"
		*s02.BridgeTimeToTriggerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeToTrigger, error) {
			var zero s00.TimeToTrigger
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TimeToTrigger, error) {
				var v struct{ Value s00.TimeToTrigger }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 16, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TimeToTrigger(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TimeToTrigger"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTimeToTriggerValueCodecFieldEncode(&sealed) = func(value s00.TimeToTrigger, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TimeToTrigger, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.TimeToTrigger }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 16, false); err != nil {
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
		*s02.BridgeTimeToTriggerValueCodecFieldCapture(&sealed) = func(v s00.TimeToTrigger, options aper.DecodeState) (s00.TimeToTrigger, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTimeToTrigger(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeToTriggerValueCodecFieldCompare(&sealed) = func(v s00.TimeToTrigger, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTimeToTrigger(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s02.BridgeTimeToTriggerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeToTrigger"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TraceDepthCodec binds the complete source value type.
func TraceDepthCodec() s02.TraceDepthValueCodec {
	return func() s02.TraceDepthValueCodec {
		sealed := s02.TraceDepthValueCodec{}
		*s02.BridgeTraceDepthValueCodecFieldPath(&sealed) = "TraceDepth"
		*s02.BridgeTraceDepthValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TraceDepth, error) {
			var zero s00.TraceDepth
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TraceDepth, error) {
				var v struct{ Value s00.TraceDepth }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TraceDepth(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceDepth"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTraceDepthValueCodecFieldEncode(&sealed) = func(value s00.TraceDepth, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TraceDepth, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.TraceDepth }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 6, true); err != nil {
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
		*s02.BridgeTraceDepthValueCodecFieldCapture(&sealed) = func(v s00.TraceDepth, options aper.DecodeState) (s00.TraceDepth, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APTraceDepth(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTraceDepthValueCodecFieldCompare(&sealed) = func(v s00.TraceDepth, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTraceDepth(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTraceDepthValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TraceDepth"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TriggeringMessageCodec binds the complete source value type.
func TriggeringMessageCodec() s02.TriggeringMessageValueCodec {
	return func() s02.TriggeringMessageValueCodec {
		sealed := s02.TriggeringMessageValueCodec{}
		*s02.BridgeTriggeringMessageValueCodecFieldPath(&sealed) = "TriggeringMessage"
		*s02.BridgeTriggeringMessageValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TriggeringMessage, error) {
			var zero s00.TriggeringMessage
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TriggeringMessage, error) {
				var v struct{ Value s00.TriggeringMessage }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TriggeringMessage(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TriggeringMessage"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTriggeringMessageValueCodecFieldEncode(&sealed) = func(value s00.TriggeringMessage, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TriggeringMessage, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.TriggeringMessage }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, false); err != nil {
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
		*s02.BridgeTriggeringMessageValueCodecFieldCapture(&sealed) = func(v s00.TriggeringMessage, options aper.DecodeState) (s00.TriggeringMessage, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTriggeringMessage(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s02.BridgeTriggeringMessageValueCodecFieldCompare(&sealed) = func(v s00.TriggeringMessage, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTriggeringMessage(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeTriggeringMessageValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TriggeringMessage"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TypeOfErrorCodec binds the complete source value type.
func TypeOfErrorCodec() s02.TypeOfErrorValueCodec {
	return func() s02.TypeOfErrorValueCodec {
		sealed := s02.TypeOfErrorValueCodec{}
		*s02.BridgeTypeOfErrorValueCodecFieldPath(&sealed) = "TypeOfError"
		*s02.BridgeTypeOfErrorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TypeOfError, error) {
			var zero s00.TypeOfError
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.TypeOfError, error) {
				var v struct{ Value s00.TypeOfError }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.TypeOfError(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "TypeOfError"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeTypeOfErrorValueCodecFieldEncode(&sealed) = func(value s00.TypeOfError, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.TypeOfError, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.TypeOfError }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
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
		*s02.BridgeTypeOfErrorValueCodecFieldCapture(&sealed) = func(v s00.TypeOfError, options aper.DecodeState) (s00.TypeOfError, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTypeOfError(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTypeOfErrorValueCodecFieldCompare(&sealed) = func(v s00.TypeOfError, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTypeOfError(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeTypeOfErrorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TypeOfError"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERLFReportContainerCodec binds the complete source value type.
func UERLFReportContainerCodec() s02.UERLFReportContainerValueCodec {
	return func() s02.UERLFReportContainerValueCodec {
		sealed := s02.UERLFReportContainerValueCodec{}
		*s02.BridgeUERLFReportContainerValueCodecFieldPath(&sealed) = "UERLFReportContainer"
		*s02.BridgeUERLFReportContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERLFReportContainer, error) {
			var zero s00.UERLFReportContainer
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.UERLFReportContainer, error) {
				var v struct{ Value s00.UERLFReportContainer }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.UERLFReportContainer(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "UERLFReportContainer"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeUERLFReportContainerValueCodecFieldEncode(&sealed) = func(value s00.UERLFReportContainer, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.UERLFReportContainer, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.UERLFReportContainer }{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeUERLFReportContainerValueCodecFieldCapture(&sealed) = func(v s00.UERLFReportContainer, options aper.DecodeState) (s00.UERLFReportContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERLFReportContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUERLFReportContainerValueCodecFieldCompare(&sealed) = func(v s00.UERLFReportContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APUERLFReportContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERLFReportContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERLFReportContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERLFReportContainerForExtendedBandsCodec binds the complete source value type.
func UERLFReportContainerForExtendedBandsCodec() s02.UERLFReportContainerForExtendedBandsValueCodec {
	return func() s02.UERLFReportContainerForExtendedBandsValueCodec {
		sealed := s02.UERLFReportContainerForExtendedBandsValueCodec{}
		*s02.BridgeUERLFReportContainerForExtendedBandsValueCodecFieldPath(&sealed) = "UERLFReportContainerForExtendedBands"
		*s02.BridgeUERLFReportContainerForExtendedBandsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERLFReportContainerForExtendedBands, error) {
			var zero s00.UERLFReportContainerForExtendedBands
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.UERLFReportContainerForExtendedBands, error) {
				var v struct {
					Value s00.UERLFReportContainerForExtendedBands
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.UERLFReportContainerForExtendedBands(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "UERLFReportContainerForExtendedBands"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeUERLFReportContainerForExtendedBandsValueCodecFieldEncode(&sealed) = func(value s00.UERLFReportContainerForExtendedBands, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.UERLFReportContainerForExtendedBands, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.UERLFReportContainerForExtendedBands
				}{Value: value}
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
			})(value, budget)
		}
		*s02.BridgeUERLFReportContainerForExtendedBandsValueCodecFieldCapture(&sealed) = func(v s00.UERLFReportContainerForExtendedBands, options aper.DecodeState) (s00.UERLFReportContainerForExtendedBands, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APUERLFReportContainerForExtendedBands(&v,
				&s,
			)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s02.BridgeUERLFReportContainerForExtendedBandsValueCodecFieldCompare(&sealed) = func(v s00.UERLFReportContainerForExtendedBands, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APUERLFReportContainerForExtendedBands(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERLFReportContainerForExtendedBandsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERLFReportContainerForExtendedBands"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ULNASCountCodec binds the complete source value type.
func ULNASCountCodec() s02.ULNASCountValueCodec {
	return func() s02.ULNASCountValueCodec {
		sealed := s02.ULNASCountValueCodec{}
		*s02.BridgeULNASCountValueCodecFieldPath(&sealed) = "ULNASCount"
		*s02.BridgeULNASCountValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ULNASCount, error) {
			var zero s00.ULNASCount
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ULNASCount, error) {
				var v struct{ Value s00.ULNASCount }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 5, 5, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ULNASCount"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeULNASCountValueCodecFieldEncode(&sealed) = func(value s00.ULNASCount, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ULNASCount, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ULNASCount }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 5, 5, true); err != nil {
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
		*s02.BridgeULNASCountValueCodecFieldCapture(&sealed) = func(v s00.ULNASCount, options aper.DecodeState) (s00.ULNASCount, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APULNASCount(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeULNASCountValueCodecFieldCompare(&sealed) = func(v s00.ULNASCount, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APULNASCount(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeULNASCountValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ULNASCount"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ULNASMACCodec binds the complete source value type.
func ULNASMACCodec() s02.ULNASMACValueCodec {
	return func() s02.ULNASMACValueCodec {
		sealed := s02.ULNASMACValueCodec{}
		*s02.BridgeULNASMACValueCodecFieldPath(&sealed) = "ULNASMAC"
		*s02.BridgeULNASMACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ULNASMAC, error) {
			var zero s00.ULNASMAC
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ULNASMAC, error) {
				var v struct{ Value s00.ULNASMAC }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ULNASMAC"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeULNASMACValueCodecFieldEncode(&sealed) = func(value s00.ULNASMAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ULNASMAC, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ULNASMAC }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true); err != nil {
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
		*s02.BridgeULNASMACValueCodecFieldCapture(&sealed) = func(v s00.ULNASMAC, options aper.DecodeState) (s00.ULNASMAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APULNASMAC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeULNASMACValueCodecFieldCompare(&sealed) = func(v s00.ULNASMAC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APULNASMAC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeULNASMACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ULNASMAC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// VehicleUECodec binds the complete source value type.
func VehicleUECodec() s02.VehicleUEValueCodec {
	return func() s02.VehicleUEValueCodec {
		sealed := s02.VehicleUEValueCodec{}
		*s02.BridgeVehicleUEValueCodecFieldPath(&sealed) = "VehicleUE"
		*s02.BridgeVehicleUEValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.VehicleUE, error) {
			var zero s00.VehicleUE
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.VehicleUE, error) {
				var v struct{ Value s00.VehicleUE }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.VehicleUE(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "VehicleUE"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeVehicleUEValueCodecFieldEncode(&sealed) = func(value s00.VehicleUE, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.VehicleUE, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.VehicleUE }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
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
		*s02.BridgeVehicleUEValueCodecFieldCapture(&sealed) = func(v s00.VehicleUE, options aper.DecodeState) (s00.VehicleUE, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APVehicleUE(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeVehicleUEValueCodecFieldCompare(&sealed) = func(v s00.VehicleUE, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APVehicleUE(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeVehicleUEValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:VehicleUE"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WLANMeasConfigCodec binds the complete source value type.
func WLANMeasConfigCodec() s02.WLANMeasConfigValueCodec {
	return func() s02.WLANMeasConfigValueCodec {
		sealed := s02.WLANMeasConfigValueCodec{}
		*s02.BridgeWLANMeasConfigValueCodecFieldPath(&sealed) = "WLANMeasConfig"
		*s02.BridgeWLANMeasConfigValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANMeasConfig, error) {
			var zero s00.WLANMeasConfig
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.WLANMeasConfig, error) {
				var v struct{ Value s00.WLANMeasConfig }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.WLANMeasConfig(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANMeasConfig"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeWLANMeasConfigValueCodecFieldEncode(&sealed) = func(value s00.WLANMeasConfig, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.WLANMeasConfig, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.WLANMeasConfig }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
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
		*s02.BridgeWLANMeasConfigValueCodecFieldCapture(&sealed) = func(v s00.WLANMeasConfig, options aper.DecodeState) (s00.WLANMeasConfig, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APWLANMeasConfig(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWLANMeasConfigValueCodecFieldCompare(&sealed) = func(v s00.WLANMeasConfig, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APWLANMeasConfig(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeWLANMeasConfigValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasConfig"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WLANNameCodec binds the complete source value type.
func WLANNameCodec() s02.WLANNameValueCodec {
	return func() s02.WLANNameValueCodec {
		sealed := s02.WLANNameValueCodec{}
		*s02.BridgeWLANNameValueCodecFieldPath(&sealed) = "WLANName"
		*s02.BridgeWLANNameValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANName, error) {
			var zero s00.WLANName
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.WLANName, error) {
				var v struct{ Value s00.WLANName }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 1, 32, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.WLANName(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANName"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s02.BridgeWLANNameValueCodecFieldEncode(&sealed) = func(value s00.WLANName, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.WLANName, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.WLANName }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 1, 32, true); err != nil {
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
		*s02.BridgeWLANNameValueCodecFieldCapture(&sealed) = func(v s00.WLANName, options aper.DecodeState) (s00.WLANName, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APWLANName(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWLANNameValueCodecFieldCompare(&sealed) = func(v s00.WLANName, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APWLANName(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeWLANNameValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANName"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldCapture(v *AdditionalGUTIExtIEsExtContainerValueCodec) *func(AdditionalGUTIExtIEsExtContainer, aper.DecodeState) (AdditionalGUTIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldCompare(v *AdditionalGUTIExtIEsExtContainerValueCodec) *func(AdditionalGUTIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldContext(v *AdditionalGUTIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldDecode(v *AdditionalGUTIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (AdditionalGUTIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldEncode(v *AdditionalGUTIExtIEsExtContainerValueCodec) *func(AdditionalGUTIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldPath(v *AdditionalGUTIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeAdditionalGUTIExtIEsExtFieldFieldReplay(v *AdditionalGUTIExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAdditionalGUTIExtIEsExtFieldFieldWithoutReplay(v *AdditionalGUTIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAdditionalGUTIExtIEsExtFieldMethodMarshalAPERTo(v *AdditionalGUTIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAdditionalGUTIExtIEsExtFieldMethodUnmarshalAPERFrom(v *AdditionalGUTIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldCapture(v *AdditionalGUTIExtIEsExtFieldValueCodec) *func(AdditionalGUTIExtIEsExtField, aper.DecodeState) (AdditionalGUTIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldCompare(v *AdditionalGUTIExtIEsExtFieldValueCodec) *func(AdditionalGUTIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldContext(v *AdditionalGUTIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldDecode(v *AdditionalGUTIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (AdditionalGUTIExtIEsExtField, error) {
	return &v.decode
}
func BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldEncode(v *AdditionalGUTIExtIEsExtFieldValueCodec) *func(AdditionalGUTIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldPath(v *AdditionalGUTIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldCapture(v *AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) *func(AllocationAndRetentionPriorityExtIEsExtContainer, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldCompare(v *AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) *func(AllocationAndRetentionPriorityExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldContext(v *AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldDecode(v *AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldEncode(v *AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) *func(AllocationAndRetentionPriorityExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldPath(v *AllocationAndRetentionPriorityExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldFieldReplay(v *AllocationAndRetentionPriorityExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldFieldWithoutReplay(v *AllocationAndRetentionPriorityExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodMarshalAPERTo(v *AllocationAndRetentionPriorityExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodUnmarshalAPERFrom(v *AllocationAndRetentionPriorityExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldCapture(v *AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) *func(AllocationAndRetentionPriorityExtIEsExtField, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldCompare(v *AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) *func(AllocationAndRetentionPriorityExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldContext(v *AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldDecode(v *AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (AllocationAndRetentionPriorityExtIEsExtField, error) {
	return &v.decode
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldEncode(v *AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) *func(AllocationAndRetentionPriorityExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldPath(v *AllocationAndRetentionPriorityExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldCapture(v *AssistanceDataForPagingExtIEsExtContainerValueCodec) *func(AssistanceDataForPagingExtIEsExtContainer, aper.DecodeState) (AssistanceDataForPagingExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldCompare(v *AssistanceDataForPagingExtIEsExtContainerValueCodec) *func(AssistanceDataForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldContext(v *AssistanceDataForPagingExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldDecode(v *AssistanceDataForPagingExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (AssistanceDataForPagingExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldEncode(v *AssistanceDataForPagingExtIEsExtContainerValueCodec) *func(AssistanceDataForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldPath(v *AssistanceDataForPagingExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceDataForPagingExtIEsExtFieldFieldReplay(v *AssistanceDataForPagingExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForPagingExtIEsExtFieldFieldWithoutReplay(v *AssistanceDataForPagingExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceDataForPagingExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceDataForPagingExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceDataForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceDataForPagingExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldCapture(v *AssistanceDataForPagingExtIEsExtFieldValueCodec) *func(AssistanceDataForPagingExtIEsExtField, aper.DecodeState) (AssistanceDataForPagingExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldCompare(v *AssistanceDataForPagingExtIEsExtFieldValueCodec) *func(AssistanceDataForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldContext(v *AssistanceDataForPagingExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldDecode(v *AssistanceDataForPagingExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (AssistanceDataForPagingExtIEsExtField, error) {
	return &v.decode
}
func BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldEncode(v *AssistanceDataForPagingExtIEsExtFieldValueCodec) *func(AssistanceDataForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldPath(v *AssistanceDataForPagingExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldCapture(v *AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) *func(AssistanceDataForRecommendedCellsExtIEsExtContainer, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldCompare(v *AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) *func(AssistanceDataForRecommendedCellsExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldContext(v *AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldDecode(v *AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldEncode(v *AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) *func(AssistanceDataForRecommendedCellsExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldPath(v *AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldFieldReplay(v *AssistanceDataForRecommendedCellsExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldFieldWithoutReplay(v *AssistanceDataForRecommendedCellsExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodMarshalAPERTo(v *AssistanceDataForRecommendedCellsExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodUnmarshalAPERFrom(v *AssistanceDataForRecommendedCellsExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldCapture(v *AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) *func(AssistanceDataForRecommendedCellsExtIEsExtField, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldCompare(v *AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) *func(AssistanceDataForRecommendedCellsExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldContext(v *AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldDecode(v *AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (AssistanceDataForRecommendedCellsExtIEsExtField, error) {
	return &v.decode
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldEncode(v *AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) *func(AssistanceDataForRecommendedCellsExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldPath(v *AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) *func(BearersSubjectToDLDiscardingItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) *func(BearersSubjectToDLDiscardingItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) *func(BearersSubjectToDLDiscardingItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldFieldReplay(v *BearersSubjectToDLDiscardingItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodMarshalAPERTo(v *BearersSubjectToDLDiscardingItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *BearersSubjectToDLDiscardingItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) *func(BearersSubjectToDLDiscardingItemExtIEsExtField, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) *func(BearersSubjectToDLDiscardingItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) *func(BearersSubjectToDLDiscardingItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldFieldReplay(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToEarlyStatusTransferItemExtIEsExtField, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToEarlyStatusTransferItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToEarlyStatusTransferItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(v *BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) *func(BluetoothMeasurementConfigurationExtIEsExtContainer, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(v *BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) *func(BluetoothMeasurementConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(v *BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(v *BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(v *BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) *func(BluetoothMeasurementConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldPath(v *BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldFieldReplay(v *BluetoothMeasurementConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v *BluetoothMeasurementConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *BluetoothMeasurementConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *BluetoothMeasurementConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(v *BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) *func(BluetoothMeasurementConfigurationExtIEsExtField, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(v *BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) *func(BluetoothMeasurementConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(v *BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(v *BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (BluetoothMeasurementConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(v *BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) *func(BluetoothMeasurementConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldPath(v *BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCGIExtIEsExtContainerValueCodecFieldCapture(v *CGIExtIEsExtContainerValueCodec) *func(CGIExtIEsExtContainer, aper.DecodeState) (CGIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCGIExtIEsExtContainerValueCodecFieldCompare(v *CGIExtIEsExtContainerValueCodec) *func(CGIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCGIExtIEsExtContainerValueCodecFieldContext(v *CGIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCGIExtIEsExtContainerValueCodecFieldDecode(v *CGIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CGIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCGIExtIEsExtContainerValueCodecFieldEncode(v *CGIExtIEsExtContainerValueCodec) *func(CGIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCGIExtIEsExtContainerValueCodecFieldPath(v *CGIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCGIExtIEsExtFieldFieldReplay(v *CGIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeCGIExtIEsExtFieldFieldWithoutReplay(v *CGIExtIEsExtField) *bool   { return &v.withoutReplay }
func BridgeCGIExtIEsExtFieldMethodMarshalAPERTo(v *CGIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCGIExtIEsExtFieldMethodUnmarshalAPERFrom(v *CGIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCGIExtIEsExtFieldValueCodecFieldCapture(v *CGIExtIEsExtFieldValueCodec) *func(CGIExtIEsExtField, aper.DecodeState) (CGIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCGIExtIEsExtFieldValueCodecFieldCompare(v *CGIExtIEsExtFieldValueCodec) *func(CGIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCGIExtIEsExtFieldValueCodecFieldContext(v *CGIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCGIExtIEsExtFieldValueCodecFieldDecode(v *CGIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CGIExtIEsExtField, error) {
	return &v.decode
}
func BridgeCGIExtIEsExtFieldValueCodecFieldEncode(v *CGIExtIEsExtFieldValueCodec) *func(CGIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCGIExtIEsExtFieldValueCodecFieldPath(v *CGIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldCapture(v *CNTypeRestrictionsItemExtIEsExtContainerValueCodec) *func(CNTypeRestrictionsItemExtIEsExtContainer, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldCompare(v *CNTypeRestrictionsItemExtIEsExtContainerValueCodec) *func(CNTypeRestrictionsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldContext(v *CNTypeRestrictionsItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldDecode(v *CNTypeRestrictionsItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldEncode(v *CNTypeRestrictionsItemExtIEsExtContainerValueCodec) *func(CNTypeRestrictionsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldPath(v *CNTypeRestrictionsItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldFieldReplay(v *CNTypeRestrictionsItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v *CNTypeRestrictionsItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(v *CNTypeRestrictionsItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CNTypeRestrictionsItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldCapture(v *CNTypeRestrictionsItemExtIEsExtFieldValueCodec) *func(CNTypeRestrictionsItemExtIEsExtField, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldCompare(v *CNTypeRestrictionsItemExtIEsExtFieldValueCodec) *func(CNTypeRestrictionsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldContext(v *CNTypeRestrictionsItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldDecode(v *CNTypeRestrictionsItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CNTypeRestrictionsItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldEncode(v *CNTypeRestrictionsItemExtIEsExtFieldValueCodec) *func(CNTypeRestrictionsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldPath(v *CNTypeRestrictionsItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldCapture(v *COUNTValueExtendedExtIEsExtContainerValueCodec) *func(COUNTValueExtendedExtIEsExtContainer, aper.DecodeState) (COUNTValueExtendedExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldCompare(v *COUNTValueExtendedExtIEsExtContainerValueCodec) *func(COUNTValueExtendedExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldContext(v *COUNTValueExtendedExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldDecode(v *COUNTValueExtendedExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (COUNTValueExtendedExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldEncode(v *COUNTValueExtendedExtIEsExtContainerValueCodec) *func(COUNTValueExtendedExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldPath(v *COUNTValueExtendedExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTValueExtendedExtIEsExtFieldFieldReplay(v *COUNTValueExtendedExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTValueExtendedExtIEsExtFieldFieldWithoutReplay(v *COUNTValueExtendedExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTValueExtendedExtIEsExtFieldMethodMarshalAPERTo(v *COUNTValueExtendedExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTValueExtendedExtIEsExtFieldMethodUnmarshalAPERFrom(v *COUNTValueExtendedExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldCapture(v *COUNTValueExtendedExtIEsExtFieldValueCodec) *func(COUNTValueExtendedExtIEsExtField, aper.DecodeState) (COUNTValueExtendedExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldCompare(v *COUNTValueExtendedExtIEsExtFieldValueCodec) *func(COUNTValueExtendedExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldContext(v *COUNTValueExtendedExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldDecode(v *COUNTValueExtendedExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (COUNTValueExtendedExtIEsExtField, error) {
	return &v.decode
}
func BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldEncode(v *COUNTValueExtendedExtIEsExtFieldValueCodec) *func(COUNTValueExtendedExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldPath(v *COUNTValueExtendedExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldCapture(v *COUNTvalueExtIEsExtContainerValueCodec) *func(COUNTvalueExtIEsExtContainer, aper.DecodeState) (COUNTvalueExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldCompare(v *COUNTvalueExtIEsExtContainerValueCodec) *func(COUNTvalueExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldContext(v *COUNTvalueExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldDecode(v *COUNTvalueExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (COUNTvalueExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldEncode(v *COUNTvalueExtIEsExtContainerValueCodec) *func(COUNTvalueExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldPath(v *COUNTvalueExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTvalueExtIEsExtFieldFieldReplay(v *COUNTvalueExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTvalueExtIEsExtFieldFieldWithoutReplay(v *COUNTvalueExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTvalueExtIEsExtFieldMethodMarshalAPERTo(v *COUNTvalueExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTvalueExtIEsExtFieldMethodUnmarshalAPERFrom(v *COUNTvalueExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldCapture(v *COUNTvalueExtIEsExtFieldValueCodec) *func(COUNTvalueExtIEsExtField, aper.DecodeState) (COUNTvalueExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldCompare(v *COUNTvalueExtIEsExtFieldValueCodec) *func(COUNTvalueExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldContext(v *COUNTvalueExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldDecode(v *COUNTvalueExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (COUNTvalueExtIEsExtField, error) {
	return &v.decode
}
func BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldEncode(v *COUNTvalueExtIEsExtFieldValueCodec) *func(COUNTvalueExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldPath(v *COUNTvalueExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldCapture(v *COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) *func(COUNTvaluePDCPSNlength18ExtIEsExtContainer, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldCompare(v *COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) *func(COUNTvaluePDCPSNlength18ExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldContext(v *COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldDecode(v *COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldEncode(v *COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) *func(COUNTvaluePDCPSNlength18ExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldPath(v *COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldFieldReplay(v *COUNTvaluePDCPSNlength18ExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldFieldWithoutReplay(v *COUNTvaluePDCPSNlength18ExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodMarshalAPERTo(v *COUNTvaluePDCPSNlength18ExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodUnmarshalAPERFrom(v *COUNTvaluePDCPSNlength18ExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldCapture(v *COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) *func(COUNTvaluePDCPSNlength18ExtIEsExtField, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldCompare(v *COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) *func(COUNTvaluePDCPSNlength18ExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldContext(v *COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldDecode(v *COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (COUNTvaluePDCPSNlength18ExtIEsExtField, error) {
	return &v.decode
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldEncode(v *COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) *func(COUNTvaluePDCPSNlength18ExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldPath(v *COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldCapture(v *CSGIdListItemExtIEsExtContainerValueCodec) *func(CSGIdListItemExtIEsExtContainer, aper.DecodeState) (CSGIdListItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldCompare(v *CSGIdListItemExtIEsExtContainerValueCodec) *func(CSGIdListItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldContext(v *CSGIdListItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldDecode(v *CSGIdListItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CSGIdListItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldEncode(v *CSGIdListItemExtIEsExtContainerValueCodec) *func(CSGIdListItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldPath(v *CSGIdListItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCSGIdListItemExtIEsExtFieldFieldReplay(v *CSGIdListItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCSGIdListItemExtIEsExtFieldFieldWithoutReplay(v *CSGIdListItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCSGIdListItemExtIEsExtFieldMethodMarshalAPERTo(v *CSGIdListItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCSGIdListItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CSGIdListItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldCapture(v *CSGIdListItemExtIEsExtFieldValueCodec) *func(CSGIdListItemExtIEsExtField, aper.DecodeState) (CSGIdListItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldCompare(v *CSGIdListItemExtIEsExtFieldValueCodec) *func(CSGIdListItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldContext(v *CSGIdListItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldDecode(v *CSGIdListItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CSGIdListItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldEncode(v *CSGIdListItemExtIEsExtFieldValueCodec) *func(CSGIdListItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldPath(v *CSGIdListItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldCapture(v *CSGMembershipInfoExtIEsExtContainerValueCodec) *func(CSGMembershipInfoExtIEsExtContainer, aper.DecodeState) (CSGMembershipInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldCompare(v *CSGMembershipInfoExtIEsExtContainerValueCodec) *func(CSGMembershipInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldContext(v *CSGMembershipInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldDecode(v *CSGMembershipInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CSGMembershipInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldEncode(v *CSGMembershipInfoExtIEsExtContainerValueCodec) *func(CSGMembershipInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldPath(v *CSGMembershipInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCSGMembershipInfoExtIEsExtFieldFieldReplay(v *CSGMembershipInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCSGMembershipInfoExtIEsExtFieldFieldWithoutReplay(v *CSGMembershipInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCSGMembershipInfoExtIEsExtFieldMethodMarshalAPERTo(v *CSGMembershipInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCSGMembershipInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *CSGMembershipInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldCapture(v *CSGMembershipInfoExtIEsExtFieldValueCodec) *func(CSGMembershipInfoExtIEsExtField, aper.DecodeState) (CSGMembershipInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldCompare(v *CSGMembershipInfoExtIEsExtFieldValueCodec) *func(CSGMembershipInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldContext(v *CSGMembershipInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldDecode(v *CSGMembershipInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CSGMembershipInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldEncode(v *CSGMembershipInfoExtIEsExtFieldValueCodec) *func(CSGMembershipInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldPath(v *CSGMembershipInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldCapture(v *CancelledCellinEAIItemExtIEsExtContainerValueCodec) *func(CancelledCellinEAIItemExtIEsExtContainer, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldCompare(v *CancelledCellinEAIItemExtIEsExtContainerValueCodec) *func(CancelledCellinEAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldContext(v *CancelledCellinEAIItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldDecode(v *CancelledCellinEAIItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldEncode(v *CancelledCellinEAIItemExtIEsExtContainerValueCodec) *func(CancelledCellinEAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldPath(v *CancelledCellinEAIItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldFieldReplay(v *CancelledCellinEAIItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v *CancelledCellinEAIItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(v *CancelledCellinEAIItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CancelledCellinEAIItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldCapture(v *CancelledCellinEAIItemExtIEsExtFieldValueCodec) *func(CancelledCellinEAIItemExtIEsExtField, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldCompare(v *CancelledCellinEAIItemExtIEsExtFieldValueCodec) *func(CancelledCellinEAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldContext(v *CancelledCellinEAIItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldDecode(v *CancelledCellinEAIItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CancelledCellinEAIItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldEncode(v *CancelledCellinEAIItemExtIEsExtFieldValueCodec) *func(CancelledCellinEAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldPath(v *CancelledCellinEAIItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldCapture(v *CancelledCellinTAIItemExtIEsExtContainerValueCodec) *func(CancelledCellinTAIItemExtIEsExtContainer, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldCompare(v *CancelledCellinTAIItemExtIEsExtContainerValueCodec) *func(CancelledCellinTAIItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldContext(v *CancelledCellinTAIItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldDecode(v *CancelledCellinTAIItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldEncode(v *CancelledCellinTAIItemExtIEsExtContainerValueCodec) *func(CancelledCellinTAIItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldPath(v *CancelledCellinTAIItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldFieldReplay(v *CancelledCellinTAIItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v *CancelledCellinTAIItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(v *CancelledCellinTAIItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *CancelledCellinTAIItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldCapture(v *CancelledCellinTAIItemExtIEsExtFieldValueCodec) *func(CancelledCellinTAIItemExtIEsExtField, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldCompare(v *CancelledCellinTAIItemExtIEsExtFieldValueCodec) *func(CancelledCellinTAIItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldContext(v *CancelledCellinTAIItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldDecode(v *CancelledCellinTAIItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CancelledCellinTAIItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldEncode(v *CancelledCellinTAIItemExtIEsExtFieldValueCodec) *func(CancelledCellinTAIItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldPath(v *CancelledCellinTAIItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldCapture(v *Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) *func(Cdma2000OneXSRVCCInfoExtIEsExtContainer, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldCompare(v *Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) *func(Cdma2000OneXSRVCCInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldContext(v *Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldDecode(v *Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldEncode(v *Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) *func(Cdma2000OneXSRVCCInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldPath(v *Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldFieldReplay(v *Cdma2000OneXSRVCCInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldFieldWithoutReplay(v *Cdma2000OneXSRVCCInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodMarshalAPERTo(v *Cdma2000OneXSRVCCInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *Cdma2000OneXSRVCCInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldCapture(v *Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) *func(Cdma2000OneXSRVCCInfoExtIEsExtField, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldCompare(v *Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) *func(Cdma2000OneXSRVCCInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldContext(v *Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldDecode(v *Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldEncode(v *Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) *func(Cdma2000OneXSRVCCInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldPath(v *Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldCapture(v *CellBasedMDTExtIEsExtContainerValueCodec) *func(CellBasedMDTExtIEsExtContainer, aper.DecodeState) (CellBasedMDTExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldCompare(v *CellBasedMDTExtIEsExtContainerValueCodec) *func(CellBasedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldContext(v *CellBasedMDTExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldDecode(v *CellBasedMDTExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CellBasedMDTExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldEncode(v *CellBasedMDTExtIEsExtContainerValueCodec) *func(CellBasedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldPath(v *CellBasedMDTExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellBasedMDTExtIEsExtFieldFieldReplay(v *CellBasedMDTExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCellBasedMDTExtIEsExtFieldFieldWithoutReplay(v *CellBasedMDTExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCellBasedMDTExtIEsExtFieldMethodMarshalAPERTo(v *CellBasedMDTExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(v *CellBasedMDTExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldCapture(v *CellBasedMDTExtIEsExtFieldValueCodec) *func(CellBasedMDTExtIEsExtField, aper.DecodeState) (CellBasedMDTExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldCompare(v *CellBasedMDTExtIEsExtFieldValueCodec) *func(CellBasedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldContext(v *CellBasedMDTExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldDecode(v *CellBasedMDTExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (CellBasedMDTExtIEsExtField, error) {
	return &v.decode
}
func BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldEncode(v *CellBasedMDTExtIEsExtFieldValueCodec) *func(CellBasedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldPath(v *CellBasedMDTExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldCapture(v *CellBasedQMCExtIEsExtContainerValueCodec) *func(CellBasedQMCExtIEsExtContainer, aper.DecodeState) (CellBasedQMCExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldCompare(v *CellBasedQMCExtIEsExtContainerValueCodec) *func(CellBasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldContext(v *CellBasedQMCExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldDecode(v *CellBasedQMCExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (CellBasedQMCExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldEncode(v *CellBasedQMCExtIEsExtContainerValueCodec) *func(CellBasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldPath(v *CellBasedQMCExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellBasedQMCExtIEsExtFieldFieldReplay(v *CellBasedQMCExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeCellBasedQMCExtIEsExtFieldFieldWithoutReplay(v *CellBasedQMCExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeCellBasedQMCExtIEsExtFieldMethodMarshalAPERTo(v *CellBasedQMCExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(v *CellBasedQMCExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestTypeExtIEsValueFieldId(v *RequestTypeExtIEsValue) *s00.ProtocolIEID { return &v.id }
func BridgeRequestTypeExtIEsValueFieldIsOpaque(v *RequestTypeExtIEsValue) *bool       { return &v.isOpaque }
func BridgeRequestTypeExtIEsValueFieldOpaque(v *RequestTypeExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeRequestTypeExtIEsValueFieldRowRequestTypeAdditionalInfo(v *RequestTypeExtIEsValue) **s00.RequestTypeAdditionalInfo {
	return &v.rowRequestTypeAdditionalInfo
}
func BridgeRequestTypeExtIEsValueMethodCaptureSemantics(v RequestTypeExtIEsValue, a0 aper.SemanticCapture) RequestTypeExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeRequestTypeExtIEsValueMethodCompareSemantics(v RequestTypeExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeRequestTypeExtIEsValueMethodDecode(v RequestTypeExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (RequestTypeExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeRequestTypeExtIEsValueMethodEncodeFresh(v RequestTypeExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeRequestTypeExtIEsValueMethodMatchesID(v RequestTypeExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeRequestTypeExtIEsValueMethodReason(v RequestTypeExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeRequestTypeExtIEsValueMethodRule(v RequestTypeExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeSupportedTAsItemExtIEsValueFieldId(v *SupportedTAsItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSupportedTAsItemExtIEsValueFieldIsOpaque(v *SupportedTAsItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeSupportedTAsItemExtIEsValueFieldOpaque(v *SupportedTAsItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSupportedTAsItemExtIEsValueFieldRowRATType(v *SupportedTAsItemExtIEsValue) **s00.RATType {
	return &v.rowRATType
}
func BridgeSupportedTAsItemExtIEsValueMethodCaptureSemantics(v SupportedTAsItemExtIEsValue, a0 aper.SemanticCapture) SupportedTAsItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeSupportedTAsItemExtIEsValueMethodCompareSemantics(v SupportedTAsItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSupportedTAsItemExtIEsValueMethodDecode(v SupportedTAsItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SupportedTAsItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeSupportedTAsItemExtIEsValueMethodEncodeFresh(v SupportedTAsItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSupportedTAsItemExtIEsValueMethodMatchesID(v SupportedTAsItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSupportedTAsItemExtIEsValueMethodReason(v SupportedTAsItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSupportedTAsItemExtIEsValueMethodRule(v SupportedTAsItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEAppLayerMeasConfigExtIEsValueFieldId(v *UEAppLayerMeasConfigExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEAppLayerMeasConfigExtIEsValueFieldIsOpaque(v *UEAppLayerMeasConfigExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeUEAppLayerMeasConfigExtIEsValueFieldOpaque(v *UEAppLayerMeasConfigExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEAppLayerMeasConfigExtIEsValueFieldRowServiceType(v *UEAppLayerMeasConfigExtIEsValue) **s00.ServiceType {
	return &v.rowServiceType
}
func BridgeUEAppLayerMeasConfigExtIEsValueMethodCaptureSemantics(v UEAppLayerMeasConfigExtIEsValue, a0 aper.SemanticCapture) UEAppLayerMeasConfigExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeUEAppLayerMeasConfigExtIEsValueMethodCompareSemantics(v UEAppLayerMeasConfigExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEAppLayerMeasConfigExtIEsValueMethodDecode(v UEAppLayerMeasConfigExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEAppLayerMeasConfigExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEAppLayerMeasConfigExtIEsValueMethodEncodeFresh(v UEAppLayerMeasConfigExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEAppLayerMeasConfigExtIEsValueMethodMatchesID(v UEAppLayerMeasConfigExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEAppLayerMeasConfigExtIEsValueMethodReason(v UEAppLayerMeasConfigExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEAppLayerMeasConfigExtIEsValueMethodRule(v UEAppLayerMeasConfigExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeUERadioCapabilityIDMappingRequestIEValueFieldId(v *UERadioCapabilityIDMappingRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUERadioCapabilityIDMappingRequestIEValueFieldIsOpaque(v *UERadioCapabilityIDMappingRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUERadioCapabilityIDMappingRequestIEValueFieldOpaque(v *UERadioCapabilityIDMappingRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUERadioCapabilityIDMappingRequestIEValueFieldRowUERadioCapabilityID(v *UERadioCapabilityIDMappingRequestIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeUERadioCapabilityIDMappingRequestIEValueMethodCaptureSemantics(v UERadioCapabilityIDMappingRequestIEValue, a0 aper.SemanticCapture) UERadioCapabilityIDMappingRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueMethodCompareSemantics(v UERadioCapabilityIDMappingRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueMethodDecode(v UERadioCapabilityIDMappingRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UERadioCapabilityIDMappingRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueMethodEncodeFresh(v UERadioCapabilityIDMappingRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueMethodMatchesID(v UERadioCapabilityIDMappingRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueMethodReason(v UERadioCapabilityIDMappingRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueMethodRule(v UERadioCapabilityIDMappingRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeWUSAssistanceInformationExtIEsValueFieldId(v *WUSAssistanceInformationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeWUSAssistanceInformationExtIEsValueFieldIsOpaque(v *WUSAssistanceInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeWUSAssistanceInformationExtIEsValueFieldOpaque(v *WUSAssistanceInformationExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeWUSAssistanceInformationExtIEsValueMethodCaptureSemantics(v WUSAssistanceInformationExtIEsValue, a0 aper.SemanticCapture) WUSAssistanceInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeWUSAssistanceInformationExtIEsValueMethodCompareSemantics(v WUSAssistanceInformationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWUSAssistanceInformationExtIEsValueMethodDecode(v WUSAssistanceInformationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (WUSAssistanceInformationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeWUSAssistanceInformationExtIEsValueMethodEncodeFresh(v WUSAssistanceInformationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWUSAssistanceInformationExtIEsValueMethodMatchesID(v WUSAssistanceInformationExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeWUSAssistanceInformationExtIEsValueMethodReason(v WUSAssistanceInformationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeWUSAssistanceInformationExtIEsValueMethodRule(v WUSAssistanceInformationExtIEsValue) aper.SourceRule {
	return v.rule()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *RequestTypeExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 298:
		if value, ok := v.AsRequestTypeAdditionalInfo(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SupportedTAsItemExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 232:
		if value, ok := v.AsRATType(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UEAppLayerMeasConfigExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 276:
		if value, ok := v.AsServiceType(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UERadioCapabilityIDMappingRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 314:
		if value, ok := v.AsUERadioCapabilityID(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *WUSAssistanceInformationExtIEsValue) Selected() (any, bool) { return nil, false }
